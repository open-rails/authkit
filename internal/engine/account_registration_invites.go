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
	q.Set("invite_code", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

func (s *Engine) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) {
	if s.email == nil {
		return
	}
	// Deliberate availability-over-consistency: the invite CREATE already succeeded
	// and the inviter got the URL back (they can share it any channel), so a failed
	// email must not fail the call — but it must be LOUD, or the recipient silently
	// never hears about the invite (#223's original bug class).
	if err := s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageInvite, To: email, Language: s.messageLanguage(ctx, ""), Link: inviteURL}); err != nil {
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
	mode := s.cfg.Registration.NativeUserMode
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
	if err := s.lockAuthority(ctx, tx); err != nil {
		return nil, err
	}
	q := db.New(tx)
	codeHash := secret.Hash(token)
	groupID, err := q.AccountInviteGroupLive(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrInvitationNotFound
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
		return nil, iam.ErrInvitationNotFound
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
	if err := db.New(tx).AccountInviteConsume(ctx, invite.ID); err != nil {
		return err
	}
	if invite.PermissionGroupID != nil && invite.Role != nil {
		var persona iam.Persona
		if invite.Persona != nil {
			persona = ident.Persona(*invite.Persona)
		}
		st := s.groupStoreFor(tx)
		st.actor = iam.UserActor(userID)
		return s.assignInvitedRole(ctx, st, *invite.PermissionGroupID, persona, userID, ident.RoleText(*invite.Role))
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
