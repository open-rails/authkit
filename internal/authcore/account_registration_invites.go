package authcore

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

const defaultAccountRegistrationInviteTTL = 7 * 24 * time.Hour

var (
	ErrAccountRegistrationInviteConsumed = authkit.ErrAccountRegistrationInviteConsumed
	ErrAccountRegistrationInviteExpired  = authkit.ErrAccountRegistrationInviteExpired
	ErrAccountRegistrationInviteNotFound = authkit.ErrAccountRegistrationInviteNotFound
	ErrAccountRegistrationInviteRevoked  = authkit.ErrAccountRegistrationInviteRevoked
)

type accountInviteTokenContextKey struct{}

func WithAccountRegistrationInviteToken(ctx context.Context, token string) context.Context {
	return contextWithAccountRegistrationInviteToken(ctx, token)
}

func (s *Service) RegistrationAllowedForEmailWithInvite(ctx context.Context, email, token string) (bool, error) {
	return s.registrationAllowedForEmail(contextWithAccountRegistrationInviteToken(ctx, token), email)
}

func (s *Service) ConsumeAccountRegistrationInvite(ctx context.Context, email, userID, token string) error {
	return s.consumeAccountRegistrationInvite(contextWithAccountRegistrationInviteToken(ctx, token), email, userID)
}

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

type AccountRegistrationInvite = authkit.AccountRegistrationInvite
type CreateAccountRegistrationInviteRequest = authkit.CreateAccountRegistrationInviteRequest
type AccountRegistrationInviteCreated = authkit.AccountRegistrationInviteCreated

type AccountRegistrationInviteMessage struct {
	InviteURL string
	Email     string
	Purpose   string
}

type AccountRegistrationInviteEmailSender interface {
	SendAccountRegistrationInvite(ctx context.Context, email string, msg AccountRegistrationInviteMessage) error
}

func (s *Service) accountRegistrationInviteURL(code string) string {
	q := url.Values{}
	q.Set("account_invite_token", code)
	return s.authkitURL(s.opts.FrontendInvitePath, q)
}

func (s *Service) CreateAccountRegistrationInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest) (AccountRegistrationInviteCreated, error) {
	return s.createAccountRegistrationInvite(ctx, req, true)
}

func (s *Service) createAccountRegistrationInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest, requireRootInvitePermission bool) (AccountRegistrationInviteCreated, error) {
	if err := s.requirePG(); err != nil {
		return AccountRegistrationInviteCreated{}, err
	}
	email := NormalizeEmail(req.Email)
	if err := ValidateEmail(email); err != nil {
		return AccountRegistrationInviteCreated{}, err
	}
	invitedBy := strings.TrimSpace(req.InvitedBy)
	if invitedBy == "" {
		return AccountRegistrationInviteCreated{}, errors.New("invalid_invite")
	}
	// A registration invite is PURELY about registration authority (#147): it is
	// gated on root:users:invite and carries no group grant — joining a group is a
	// SEPARATE invite under members:manage. (The rare stranger-into-group-while-
	// invite-only case is just two separate links.)
	if requireRootInvitePermission {
		ok, err := s.Can(ctx, invitedBy, SubjectKindUser, RootPersona, "", PermRootUsersInvite)
		if err != nil {
			return AccountRegistrationInviteCreated{}, err
		}
		if !ok {
			return AccountRegistrationInviteCreated{}, ErrInsufficientRoleAuthority
		}
	}
	ttl := req.ExpiresIn
	if ttl <= 0 {
		ttl = defaultAccountRegistrationInviteTTL
	}
	expiresAt := time.Now().UTC().Add(ttl)
	code := randB64(32)
	codeHash := sha256Hex(code)
	q := db.ForSchema(s.pg, s.dbSchema())
	var id string
	err := q.QueryRow(ctx,
		`INSERT INTO profiles.account_registration_invites (email, invited_by, code_hash, expires_at)
		 VALUES ($1, $2::uuid, $3, $4)
		 RETURNING id::text`,
		email, invitedBy, codeHash, expiresAt).Scan(&id)
	if err != nil {
		return AccountRegistrationInviteCreated{}, err
	}
	created := AccountRegistrationInviteCreated{
		ID:        id,
		Code:      code,
		URL:       s.accountRegistrationInviteURL(code),
		Email:     email,
		ExpiresAt: expiresAt,
	}
	s.sendAccountRegistrationInviteEmail(ctx, email, created.URL)
	return created, nil
}

func (s *Service) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) {
	if s.email == nil {
		return
	}
	sender, ok := s.email.(AccountRegistrationInviteEmailSender)
	if !ok {
		return
	}
	msg := AccountRegistrationInviteMessage{InviteURL: inviteURL, Email: email, Purpose: "account_registration_invite"}
	_ = s.withSendTimeout(ctx, func(sendCtx context.Context) error {
		return sender.SendAccountRegistrationInvite(sendCtx, email, msg)
	})
}

func (s *Service) RevokeAccountRegistrationInvite(ctx context.Context, inviteID, actorUserID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	inviteID = strings.TrimSpace(inviteID)
	actorUserID = strings.TrimSpace(actorUserID)
	if inviteID == "" || actorUserID == "" {
		return errors.New("invalid_invite")
	}
	ok, err := s.Can(ctx, actorUserID, SubjectKindUser, RootPersona, "", PermRootUsersInvite)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInsufficientRoleAuthority
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.account_registration_invites
		 SET revoked_at = now(), updated_at = now()
		 WHERE id = $1::uuid AND revoked_at IS NULL AND consumed_at IS NULL`,
		inviteID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountRegistrationInviteNotFound
	}
	return nil
}

func (s *Service) hasValidAccountRegistrationInvite(ctx context.Context, email string) (bool, error) {
	// #147 FINAL: the stranger invite is UNBOUND — the single-use code is the
	// credential, not the address it was delivered to. We check only that a valid,
	// unconsumed, unexpired code is presented; `email` (the registrant's chosen
	// address) is irrelevant to authorization. Whoever holds the link may register.
	token := accountRegistrationInviteTokenFromContext(ctx)
	if token == "" || s.pg == nil {
		return false, nil
	}
	_ = email
	q := db.ForSchema(s.pg, s.dbSchema())
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM profiles.account_registration_invites
		   WHERE code_hash = $1 AND revoked_at IS NULL
		     AND consumed_at IS NULL AND expires_at > now()
		 )`,
		sha256Hex(token)).Scan(&exists)
	return exists, err
}

func (s *Service) consumeAccountRegistrationInvite(ctx context.Context, email, userID string) error {
	mode, err := normalizeRegistrationMode(s.opts.NativeUserRegistrationMode)
	if err != nil || mode != RegistrationModeInviteOnly {
		return nil
	}
	_ = email // #147 FINAL: unbound — consumed by code, not by address.
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("invalid_user")
	}
	token := accountRegistrationInviteTokenFromContext(ctx)
	if token == "" {
		// Unbound consumption is keyed solely on the code; with none presented
		// there is nothing to consume (registration only reached here under a valid
		// code via hasValidAccountRegistrationInvite).
		return nil
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.account_registration_invites
		 SET consumed_at = now(), consumed_by = $2::uuid, updated_at = now()
		 WHERE id = (
		   SELECT id FROM profiles.account_registration_invites
		   WHERE code_hash = $1 AND revoked_at IS NULL
		     AND consumed_at IS NULL AND expires_at > now()
		   LIMIT 1
		 )`,
		sha256Hex(token), userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountRegistrationInviteNotFound
	}
	return nil
}
