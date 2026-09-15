package embedded

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

func (s *Client) RegistrationAllowedForEmailWithInvite(ctx context.Context, email, token string) (bool, error) {
	return s.registrationAllowedForEmail(contextWithAccountRegistrationInviteToken(ctx, token), email)
}

func (s *Client) ConsumeAccountRegistrationInvite(ctx context.Context, email, userID, token string) error {
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

func (s *Client) accountRegistrationInviteURL(code string) string {
	q := url.Values{}
	q.Set("account_invite_token", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

func (s *Client) CreateAccountRegistrationInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest) (AccountRegistrationInviteCreated, error) {
	return s.createAccountRegistrationInvite(ctx, req, true)
}

func (s *Client) createAccountRegistrationInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest, requireRootInvitePermission bool) (AccountRegistrationInviteCreated, error) {
	if err := s.requirePG(); err != nil {
		return AccountRegistrationInviteCreated{}, err
	}
	email := NormalizeEmail(req.Email)
	if err := ValidateEmail(email); err != nil {
		return AccountRegistrationInviteCreated{}, err
	}
	invitedBy := strings.TrimSpace(req.InvitedBy)
	if invitedBy == "" {
		return AccountRegistrationInviteCreated{}, authkit.ErrInvalidInvite
	}

	// #147 register+join: an invite OPTIONALLY carries a group role it ALSO grants on
	// consume. The two halves authorize differently:
	//   - plain registration invite (no role) -> root:users:invite (general onboarding).
	//   - role-carrying invite -> that group's members:manage no-escalation ONLY (the
	//     same mint gate as CreateGroupInviteLink). A member-manager may attach a
	//     registration credential scoped to THIS invite without gaining general
	//     root:users:invite authority.
	group := authkit.GroupRef{Persona: authkit.Persona(strings.TrimSpace(string(req.Persona))), Instance: strings.TrimSpace(req.InstanceSlug)}
	persona := group.Persona
	role := authkit.Role(strings.ToLower(strings.TrimSpace(string(req.Role))))
	carriesRole := persona != "" && role != ""

	var groupID *string
	if carriesRole {
		if !s.externalInvitesEnabled() {
			return AccountRegistrationInviteCreated{}, ErrExternalInvitesDisabled
		}
		st := s.groupStore()
		sch := s.groupSchemaOrDefault()
		if !s.validRoleForPersona(sch, persona, role) {
			return AccountRegistrationInviteCreated{}, fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, authkit.ErrRoleNotAssignable)
		}
		gid, err := s.resolveGroupID(ctx, st, group)
		if err != nil {
			return AccountRegistrationInviteCreated{}, err
		}
		groupID = &gid
	} else if requireRootInvitePermission {
		ok, err := s.Can(ctx, authkit.UserSubject(invitedBy), authkit.RootGroup(), PermRootUsersInvite)
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
	code := RandB64(32)
	codeHash := sha256Hex(code)
	var roleParam *authkit.Role
	if carriesRole {
		roleParam = &role
	}
	var id string
	insert := func(q db.DBTX) error {
		return q.QueryRow(ctx,
			`INSERT INTO profiles.account_registration_invites (email, invited_by, code_hash, expires_at, permission_group_id, role)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6)
		 RETURNING id::text`,
			email, invitedBy, codeHash, expiresAt, groupID, roleParam).Scan(&id)

	}
	var err error
	if groupID != nil {
		err = s.withLockedGroup(ctx, *groupID, func(st *PermissionGroupStore) error {
			if err := s.authorizeRoleChange(ctx, st, s.groupSchemaOrDefault(), persona, *groupID, invitedBy, role); err != nil {
				return err
			}
			return insert(st.q)
		})
	} else {
		err = insert(db.ForSchema(s.pg, s.dbSchema()))
	}
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
		created.InstanceSlug = group.Instance
		created.Role = role
	}
	s.sendAccountRegistrationInviteEmail(ctx, email, created.URL)
	return created, nil
}

func (s *Client) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) {
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

func (s *Client) hasValidAccountRegistrationInvite(ctx context.Context, email string) (bool, error) {
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

type registrationInvite struct {
	ID      string
	GroupID *string
	Role    *authkit.Role
	Persona *authkit.Persona
}

func (s *Client) lockRegistrationInvite(ctx context.Context, tx pgx.Tx, token string) (*registrationInvite, error) {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	if err != nil || mode == RegistrationModeClosed {
		return nil, ErrRegistrationDisabled
	}
	token = strings.TrimSpace(token)
	if token == "" {
		if mode == RegistrationModeInviteOnly {
			return nil, ErrRegistrationDisabled
		}
		return nil, nil
	}
	q := db.ForSchema(tx, s.dbSchema())
	var groupID *string
	err = q.QueryRow(ctx, `SELECT permission_group_id::text FROM profiles.account_registration_invites WHERE code_hash=$1 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>now()`, sha256Hex(token)).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	if groupID != nil {
		if err := lockPermissionGroup(ctx, q, *groupID); err != nil {
			return nil, err
		}
	}
	var invite registrationInvite
	err = db.ForSchema(tx, s.dbSchema()).QueryRow(ctx, `SELECT i.id::text,i.permission_group_id::text,i.role,g.persona
FROM profiles.account_registration_invites i LEFT JOIN profiles.permission_groups g ON g.id=i.permission_group_id
WHERE i.code_hash=$1 AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at>now()
AND i.permission_group_id IS NOT DISTINCT FROM $2::uuid
FOR UPDATE OF i`, sha256Hex(token), groupID).Scan(&invite.ID, &invite.GroupID, &invite.Role, &invite.Persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

func (s *Client) applyRegistrationInvite(ctx context.Context, tx pgx.Tx, invite *registrationInvite, userID string) error {
	if invite == nil {
		return nil
	}
	q := db.ForSchema(tx, s.dbSchema())
	if _, err := q.Exec(ctx, `UPDATE profiles.account_registration_invites SET consumed_at=now(),consumed_by=$2::uuid,updated_at=now() WHERE id=$1::uuid`, invite.ID, userID); err != nil {
		return err
	}
	if invite.GroupID != nil && invite.Role != nil {
		var persona authkit.Persona
		if invite.Persona != nil {
			persona = *invite.Persona
		}
		if err := s.requireMFAForRoleAssignment(ctx, q, *invite.GroupID, persona, authkit.UserSubject(userID), *invite.Role); err != nil {
			return err
		}
		return NewPermissionGroupStore(q).AssignRole(ctx, *invite.GroupID, authkit.UserSubject(userID), *invite.Role)
	}
	return nil
}

func (s *Client) consumeAccountRegistrationInvite(ctx context.Context, _ string, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.New("invalid_user")
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
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
