package authcore

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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

// CreateAccountRegistrationInviteForGroupInvite mints the standalone
// account-registration token that accompanies an unknown-email permission-group
// invite under InviteOnly. The caller must already have passed the group invite's
// members:manage/no-escalation authorization.
func (s *Service) CreateAccountRegistrationInviteForGroupInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest) (AccountRegistrationInviteCreated, error) {
	return s.createAccountRegistrationInvite(ctx, req, false)
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
	// Optional permission-group grant (#147): persona+role required together;
	// instance "" is the singleton root group. All NULL = a pure registration invite.
	var grantPersona, grantInstance, grantRole *string
	if p := strings.TrimSpace(req.GroupPersona); p != "" || strings.TrimSpace(req.GroupRole) != "" {
		role := strings.TrimSpace(req.GroupRole)
		if p == "" || role == "" {
			return AccountRegistrationInviteCreated{}, errors.New("invalid_invite: group grant needs both persona and role")
		}
		inst := strings.TrimSpace(req.GroupInstanceSlug)
		grantPersona, grantInstance, grantRole = &p, &inst, &role
	}
	// Authorize by the credential the code actually confers (#147): a code that
	// joins a GROUP is authorized by that group's role-assignment authority
	// (members:manage + no-escalation); a pure account-registration code by the
	// root `root:users:invite` permission.
	if grantPersona != nil {
		sch := s.groupSchemaOrDefault()
		if !s.validRoleForPersona(sch, *grantPersona, *grantRole) {
			return AccountRegistrationInviteCreated{}, errors.New("invalid_role")
		}
		st := s.groupStore()
		gid, err := s.resolveGroupID(ctx, st, *grantPersona, *grantInstance)
		if err != nil {
			return AccountRegistrationInviteCreated{}, err
		}
		if err := s.authorizeRoleChange(ctx, st, sch, *grantPersona, gid, invitedBy, *grantRole); err != nil {
			return AccountRegistrationInviteCreated{}, err
		}
	} else if requireRootInvitePermission {
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
		`INSERT INTO profiles.account_registration_invites
		   (email, invited_by, code_hash, expires_at, grant_persona, grant_instance_slug, grant_role)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7)
		 RETURNING id::text`,
		email, invitedBy, codeHash, expiresAt, grantPersona, grantInstance, grantRole).Scan(&id)
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
	token := accountRegistrationInviteTokenFromContext(ctx)
	if token == "" {
		// Unbound consumption is keyed solely on the code; with none presented
		// there is nothing to consume (registration only reached here under a valid
		// code via hasValidAccountRegistrationInvite).
		return nil
	}
	return s.redeemAccountRegistrationInviteCode(ctx, token, userID)
}

// RedeemAccountRegistrationInvite consumes an account-registration invite code for
// an ALREADY-signed-in user (#147): the stranger link, when opened by someone who
// already has — or has just created — an account, is redeemed here. If the code
// carried a permission-group grant, the user is added to that group/role. Single-use.
func (s *Service) RedeemAccountRegistrationInvite(ctx context.Context, code, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(code) == "" {
		return ErrAccountRegistrationInviteNotFound
	}
	return s.redeemAccountRegistrationInviteCode(ctx, code, userID)
}

// redeemAccountRegistrationInviteCode atomically marks the code consumed (single-use)
// and, if it carries a group grant, adds userID to that group/role.
func (s *Service) redeemAccountRegistrationInviteCode(ctx context.Context, code, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("invalid_user")
	}
	tokenHash := sha256Hex(code)
	q := db.ForSchema(s.pg, s.dbSchema())
	var persona, instance, role *string
	var consumedID string
	err := q.QueryRow(ctx,
		`UPDATE profiles.account_registration_invites
		 SET consumed_at = now(), consumed_by = $2::uuid, updated_at = now()
		 WHERE id = (
		   SELECT id FROM profiles.account_registration_invites
		   WHERE code_hash = $1 AND revoked_at IS NULL
		     AND consumed_at IS NULL AND expires_at > now()
		   LIMIT 1
		 )
		 RETURNING id::text, grant_persona, grant_instance_slug, grant_role`,
		tokenHash, userID).Scan(&consumedID, &persona, &instance, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return err
	}
	// Optional group grant: add the user to the carried group/role on consume.
	// ponytail: consume + grant are not one transaction; AssignGroupRole is
	// store-idempotent, so a rare post-consume grant failure is recoverable by
	// re-adding the member rather than worth a tx-threaded grant here.
	if persona != nil && role != nil {
		inst := ""
		if instance != nil {
			inst = *instance
		}
		if gErr := s.AssignGroupRole(ctx, *persona, inst, userID, SubjectKindUser, *role); gErr != nil {
			return gErr
		}
	}
	return nil
}
