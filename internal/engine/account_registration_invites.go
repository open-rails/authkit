package engine

// A sign-up's invitation: an invite link or an email invitation. Its code is
// the credential that admits the registration, under invite_only too, and the
// registration redeems it in its own transaction, landing the role. An email
// invitation whose code went only to its address proves that address.

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/secret"
)

const defaultAccountRegistrationInviteTTL = 7 * 24 * time.Hour

type accountInviteTokenContextKey struct{}

func contextWithAccountRegistrationInviteToken(ctx context.Context, token string) context.Context {
	token = strings.TrimSpace(token)
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, accountInviteTokenContextKey{}, token)
}

type registrationAgreementsContextKey struct{}

// contextWithRegistrationAgreements carries a sign-up's accepted documents
// from its start to the pending registration it stores, as the invitation
// token is carried.
func contextWithRegistrationAgreements(ctx context.Context, refs []iam.AgreementRef) context.Context {
	if len(refs) == 0 {
		return ctx
	}
	return context.WithValue(ctx, registrationAgreementsContextKey{}, refs)
}

func registrationAgreementsFromContext(ctx context.Context) []iam.AgreementRef {
	refs, _ := ctx.Value(registrationAgreementsContextKey{}).([]iam.AgreementRef)
	return refs
}

func accountRegistrationInviteTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(accountInviteTokenContextKey{}).(string)
	return strings.TrimSpace(token)
}

func (s *Engine) accountRegistrationInviteURL(code string) string {
	q := url.Values{}
	q.Set("invite_code", code)
	return s.authkitURL(config.InvitePath, q)
}

// sendAccountRegistrationInviteEmail emails the invitation when email is
// available, reporting whether it went. A failed send does not fail the
// invitation: the inviter gets its URL to share instead.
func (s *Engine) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) bool {
	if !s.EmailAvailable() {
		return false
	}
	if err := s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageInvite, To: email, Language: s.messageLanguage(ctx, ""), Link: inviteURL}); err != nil {
		s.log.ErrorContext(ctx, "authkit: account-registration invite email failed; the inviter holds its URL", "error", err)
		return false
	}
	return true
}

// signUpInvite is a live invitation presented at sign-up.
type signUpInvite struct {
	invitation
	email   string // the invited address; "" for a link
	emailed bool   // its code went to email and nowhere else
}

// proves reports whether registering address with the invitation proves it:
// the code was emailed there and to no one else.
func (i *signUpInvite) proves(address string) bool {
	return i != nil && i.emailed && address != "" && contact.NormalizeEmail(address) == contact.NormalizeEmail(i.email)
}

// presentedInvite is the live invitation whose code is token, nil for no
// token. A code that is not live is refused: unknown or used
// (ErrInvitationNotFound), revoked, or expired.
func (s *Engine) presentedInvite(ctx context.Context, token string) (*signUpInvite, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	return s.liveInvite(ctx, s.groupStore(), token)
}

// lockRegistrationInvite admits a registration in tx, the authority
// transaction that creates the account: closed admits none, invite_only only
// one presenting a live invitation, which it locks for redeeming.
func (s *Engine) lockRegistrationInvite(ctx context.Context, tx pgx.Tx, token string) (*signUpInvite, error) {
	mode := s.cfg.Registration
	if mode == iam.RegistrationModeClosed {
		return nil, errmodel.ErrRegistrationDisabled
	}
	token = strings.TrimSpace(token)
	if token == "" {
		if mode == iam.RegistrationModeInviteOnly {
			return nil, errmodel.ErrRegistrationDisabled
		}
		return nil, nil
	}
	if err := s.invitationsOn(); err != nil {
		return nil, err
	}
	if err := s.lockAuthority(ctx, tx); err != nil {
		return nil, err
	}
	st := s.groupStoreFor(tx)
	q := db.New(tx)
	found, err := q.InvitationByCode(ctx, db.InvitationByCodeParams{TenantID: s.tenantKey(ctx), CodeHash: secret.Hash(token)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrInvitationNotFound
	}
	if err != nil {
		return nil, err
	}
	// The group before the invitation, as every authority change locks them.
	if found.GroupID != "" {
		if err := lockPermissionGroup(ctx, tx, found.GroupID); err != nil {
			return nil, err
		}
	}
	if found.Kind == "group_invite_links" {
		err = q.InviteLinkLock(ctx, found.ID)
	} else {
		err = q.AccountInviteLock(ctx, found.ID)
	}
	if err != nil {
		return nil, err
	}
	return s.liveInvite(ctx, st, token)
}

// liveInvite reads the invitation whose code is token and refuses it unless
// it is live.
func (s *Engine) liveInvite(ctx context.Context, st *permissionGroupStore, token string) (*signUpInvite, error) {
	if err := s.invitationsOn(); err != nil {
		return nil, err
	}
	row, err := db.New(st.q).InvitationByCode(ctx, db.InvitationByCodeParams{TenantID: s.tenantKey(ctx), CodeHash: secret.Hash(token)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrInvitationNotFound
	}
	if err != nil {
		return nil, err
	}
	inv := &signUpInvite{
		invitation: invitation{
			table: row.Kind, id: row.ID, group: groupTarget{ID: row.GroupID, Persona: ident.Persona(row.Persona)}, role: ident.RoleText(row.Role),
			used: row.UsedAt != nil, revoked: row.RevokedAt != nil, issuerLive: row.IssuerLive, expiresAt: row.ExpiresAt,
		},
		email: row.Email, emailed: row.Emailed,
	}
	if err := s.standingInvitation(ctx, st, inv.invitation); err != nil {
		return nil, err
	}
	if inv.used {
		return nil, iam.ErrInvitationNotFound
	}
	return inv, nil
}

// applyRegistrationInvite redeems invite for userID, the account its
// registration just created in tx, landing its role.
func (s *Engine) applyRegistrationInvite(ctx context.Context, tx pgx.Tx, invite *signUpInvite, userID string) error {
	if invite == nil {
		return nil
	}
	st := s.groupStoreFor(tx)
	st.who = iam.UserIdentity(userID)
	return s.redeemInvitation(ctx, st, invite.invitation, nativeHolder{s: s, id: userID})
}
