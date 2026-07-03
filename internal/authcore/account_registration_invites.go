package authcore

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
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

func (s *Service) accountRegistrationInviteURL(code string) string {
	q := url.Values{}
	q.Set("account_invite_token", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
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

	// #147 register+join: an invite OPTIONALLY carries a group role it ALSO grants on
	// consume. The two halves authorize differently:
	//   - plain registration invite (no role) -> root:users:invite (general onboarding).
	//   - role-carrying invite -> that group's members:manage no-escalation ONLY (the
	//     same mint gate as CreateGroupInviteLink). A member-manager may attach a
	//     registration credential scoped to THIS invite without gaining general
	//     root:users:invite authority.
	persona := strings.TrimSpace(req.Persona)
	instanceSlug := strings.TrimSpace(req.InstanceSlug)
	role := strings.ToLower(strings.TrimSpace(req.Role))
	carriesRole := persona != "" && role != ""

	var groupID *string
	if carriesRole {
		if !s.externalInvitesEnabled() {
			return AccountRegistrationInviteCreated{}, ErrExternalInvitesDisabled
		}
		st := s.groupStore()
		sch := s.groupSchemaOrDefault()
		if !s.validRoleForPersona(sch, persona, role) {
			return AccountRegistrationInviteCreated{}, fmt.Errorf("role %q is not assignable in a %q group", role, persona)
		}
		gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
		if err != nil {
			return AccountRegistrationInviteCreated{}, err
		}
		// AK2-AUTHZ-1: a deferred role grant must pass the same no-escalation check
		// every grant surface uses (mirrors CreateGroupInviteLink's mint gate).
		if err := s.authorizeRoleChange(ctx, st, sch, persona, gid, invitedBy, role); err != nil {
			return AccountRegistrationInviteCreated{}, err
		}
		groupID = &gid
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
	var roleParam *string
	if carriesRole {
		roleParam = &role
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	var id string
	err := q.QueryRow(ctx,
		`INSERT INTO profiles.account_registration_invites (email, invited_by, code_hash, expires_at, permission_group_id, role)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6)
		 RETURNING id::text`,
		email, invitedBy, codeHash, expiresAt, groupID, roleParam).Scan(&id)
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
	if carriesRole {
		created.Persona = persona
		created.InstanceSlug = instanceSlug
		created.Role = role
	}
	s.sendAccountRegistrationInviteEmail(ctx, email, created.URL)
	return created, nil
}

func (s *Service) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) {
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
	_ = email // #147 FINAL: unbound — consumed by code, not by address.
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("invalid_user")
	}
	token := accountRegistrationInviteTokenFromContext(ctx)
	if token == "" || s.pg == nil {
		// No code presented. Under InviteOnly the registration gate
		// (hasValidAccountRegistrationInvite) already ran; there is nothing to consume.
		return nil
	}
	mode, _ := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)

	// Claim the code and apply any carried group grant in ONE transaction, so a
	// register+join can never mark the code used without also assigning the role
	// (#147). Mirrors RedeemGroupInviteLink's FOR UPDATE + assign-then-mark pattern.
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())

	var inviteID string
	var groupID, role, persona *string // group/role NULL for a plain registration invite
	err = q.QueryRow(ctx,
		`SELECT i.id::text, i.permission_group_id::text, i.role, g.persona
		   FROM profiles.account_registration_invites i
		   LEFT JOIN profiles.permission_groups g
		     ON g.id = i.permission_group_id
		  WHERE i.code_hash = $1 AND i.revoked_at IS NULL
		    AND i.consumed_at IS NULL AND i.expires_at > now()
		  FOR UPDATE OF i`,
		sha256Hex(token)).Scan(&inviteID, &groupID, &role, &persona)
	if errors.Is(err, pgx.ErrNoRows) {
		// No live code matched. Under InviteOnly the code WAS the registration
		// authority, so its absence is an error; otherwise the token was optional.
		if mode == RegistrationModeInviteOnly {
			return ErrAccountRegistrationInviteNotFound
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx,
		`UPDATE profiles.account_registration_invites
		 SET consumed_at = now(), consumed_by = $2::uuid, updated_at = now()
		 WHERE id = $1::uuid`,
		inviteID, userID); err != nil {
		return err
	}
	// register+join: grant the carried group role to the freshly-registered user.
	if groupID != nil && role != nil && strings.TrimSpace(*groupID) != "" && strings.TrimSpace(*role) != "" {
		p := ""
		if persona != nil {
			p = *persona
		}
		if err := s.requireMFAForRoleAssignment(ctx, q, p, userID, SubjectKindUser, *role); err != nil {
			return err
		}
		if err := NewPermissionGroupStore(q).AssignRole(ctx, *groupID, userID, SubjectKindUser, *role); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
