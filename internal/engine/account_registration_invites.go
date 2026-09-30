package engine

import (
	"context"
	"errors"
	stdlog "log"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
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

func accountRegistrationInviteTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(accountInviteTokenContextKey{}).(string)
	return strings.TrimSpace(token)
}

func (s *Engine) accountRegistrationInviteURL(code string) string {
	q := url.Values{}
	q.Set("account_invite_token", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

// CreateAccountInvite invites i.Email to register. A plain invite needs
// CAP(root:users:invite) on root. With i.Group and i.Role set, registering also
// grants that role, and the invite needs that group's CAP(<p>:members:manage)
// plus COVER(role) instead (the invite-link rule), not root:users:invite. Only
// a user or the system issues credentials. The code is returned once and
// emailed to i.Email.
func (s *Engine) CreateAccountInvite(ctx context.Context, a iam.Actor, i iam.NewAccountInvite) (iam.AccountInviteCreated, error) {
	creator, err := credentialIssuer(a)
	if err != nil {
		return iam.AccountInviteCreated{}, err
	}
	email := contact.NormalizeEmail(i.Email)
	if err := contact.ValidateEmail(email); err != nil {
		return iam.AccountInviteCreated{}, err
	}
	role := i.Role
	carriesRole := !i.Group.IsZero()
	if carriesRole != !role.IsZero() {
		return iam.AccountInviteCreated{}, errmodel.ErrInvalidInvite
	}
	if carriesRole && !s.externalInvitesEnabled() {
		return iam.AccountInviteCreated{}, iam.ErrExternalInvitesDisabled
	}
	ref := iam.RootGroup()
	if carriesRole {
		ref = i.Group
	}
	ttl := i.ExpiresIn
	if ttl <= 0 {
		ttl = defaultAccountRegistrationInviteTTL
	}
	out := iam.AccountInviteCreated{Code: secret.Token(32), Email: email, ExpiresAt: time.Now().UTC().Add(ttl)}
	err = s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		var groupID, roleParam *string
		if carriesRole {
			if _, err := s.requireIssuableRole(ctx, st, g, role); err != nil {
				return err
			}
			if err := s.requireRoleGrant(ctx, st, a, g, iam.PermMembersManage(g.Persona), role); err != nil {
				return err
			}
			name := role.Name()
			groupID, roleParam = &g.ID, &name
		} else {
			auth, err := s.actorAuthority(ctx, st, a, g)
			if err != nil {
				return err
			}
			if err := auth.requireCap(iam.PermRootUsersInvite); err != nil {
				return err
			}
		}
		id, err := db.New(st.q).AccountInviteInsert(ctx, db.AccountInviteInsertParams{
			Email: email, InvitedBy: nullable(creator), CodeHash: secret.Hash(out.Code), ExpiresAt: out.ExpiresAt, GroupID: groupID, Role: roleParam,
		})
		out.ID = id
		return err
	})
	if err != nil {
		return iam.AccountInviteCreated{}, err
	}
	out.URL = s.accountRegistrationInviteURL(out.Code)
	s.sendAccountRegistrationInviteEmail(ctx, email, out.URL)
	return out, nil
}

func (s *Engine) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) {
	if s.email == nil {
		return
	}
	// Deliberate availability-over-consistency: the invite CREATE already succeeded
	// and the inviter got the URL back (they can share it any channel), so a failed
	// email must not fail the call — but it must be LOUD, or the recipient silently
	// never hears about the invite (#223's original bug class).
	if err := s.withSendTimeout(ctx, func(sendCtx context.Context) error {
		return s.email.SendAccountRegistrationInvite(sendCtx, email, inviteURL)
	}); err != nil {
		stdlog.Printf("authkit: error: account-registration invite email send failed (invite created; inviter still holds the URL): %v", err)
	}
}

func (s *Engine) hasValidAccountRegistrationInvite(ctx context.Context, email string) (bool, error) {
	// #147 FINAL: the stranger invite is UNBOUND — the single-use code is the
	// credential, not the address it was delivered to. We check only that a valid,
	// unconsumed, unexpired code is presented; `email` (the registrant's chosen
	// address) is irrelevant to authorization. Whoever holds the link may register.
	token := accountRegistrationInviteTokenFromContext(ctx)
	if token == "" || s.pg == nil {
		return false, nil
	}
	_ = email
	return s.q.AccountInviteValid(ctx, secret.Hash(token))
}

func (s *Engine) lockRegistrationInvite(ctx context.Context, tx pgx.Tx, token string) (*db.AccountInviteForUpdateRow, error) {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	if err != nil || mode == iam.RegistrationModeClosed {
		return nil, errmodel.ErrRegistrationDisabled
	}
	token = strings.TrimSpace(token)
	if token == "" {
		if mode == iam.RegistrationModeInviteOnly {
			return nil, errmodel.ErrRegistrationDisabled
		}
		return nil, nil
	}
	if err := s.lockAuthority(ctx, tx); err != nil {
		return nil, err
	}
	q := db.New(tx)
	codeHash := secret.Hash(token)
	groupID, err := q.AccountInviteGroupLive(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errmodel.ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	if groupID != nil {
		if err := lockPermissionGroup(ctx, tx, *groupID); err != nil {
			return nil, err
		}
	}
	invite, err := q.AccountInviteForUpdate(ctx, db.AccountInviteForUpdateParams{CodeHash: codeHash, GroupID: groupID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errmodel.ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

func (s *Engine) applyRegistrationInvite(ctx context.Context, tx pgx.Tx, invite *db.AccountInviteForUpdateRow, userID string) error {
	if invite == nil {
		return nil
	}
	if err := db.New(tx).AccountInviteConsume(ctx, db.AccountInviteConsumeParams{ID: invite.ID, UserID: userID}); err != nil {
		return err
	}
	if invite.PermissionGroupID != nil && invite.Role != nil {
		var persona iam.Persona
		if invite.Persona != nil {
			persona = ident.Persona(*invite.Persona)
		}
		st := s.groupStoreFor(tx)
		st.actor = iam.UserActor(userID)
		return s.assignInvitedRole(ctx, st, *invite.PermissionGroupID, persona, userID, ident.Role(persona, *invite.Role))
	}
	return nil
}

func (s *Engine) consumeAccountRegistrationInvite(ctx context.Context, _ string, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.New("invalid_user")
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	invite, err := s.lockRegistrationInvite(ctx, tx, accountRegistrationInviteTokenFromContext(ctx))
	if err != nil {
		return err
	}
	if err := s.applyRegistrationInvite(ctx, tx, invite, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
