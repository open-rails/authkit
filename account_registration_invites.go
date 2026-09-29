package authkit

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/secret"
)

const defaultAccountRegistrationInviteTTL = 7 * 24 * time.Hour

type accountInviteTokenContextKey struct{}

func withAccountRegistrationInviteToken(ctx context.Context, token string) context.Context {
	return contextWithAccountRegistrationInviteToken(ctx, token)
}

func (s *engine) RegistrationAllowedForEmailWithInvite(ctx context.Context, email, token string) (bool, error) {
	return s.registrationAllowedForEmail(contextWithAccountRegistrationInviteToken(ctx, token), email)
}

func (s *engine) ConsumeAccountRegistrationInvite(ctx context.Context, email, userID, token string) error {
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

func (s *engine) accountRegistrationInviteURL(code string) string {
	q := url.Values{}
	q.Set("account_invite_token", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

func (s *engine) CreateAccountRegistrationInvite(ctx context.Context, req authflow.CreateAccountRegistrationInviteRequest) (authflow.AccountRegistrationInviteCreated, error) {
	return s.createAccountRegistrationInvite(ctx, req, true)
}

func (s *engine) createAccountRegistrationInvite(ctx context.Context, req authflow.CreateAccountRegistrationInviteRequest, requireRootInvitePermission bool) (authflow.AccountRegistrationInviteCreated, error) {
	if err := s.requirePG(); err != nil {
		return authflow.AccountRegistrationInviteCreated{}, err
	}
	email := contact.NormalizeEmail(req.Email)
	if err := contact.ValidateEmail(email); err != nil {
		return authflow.AccountRegistrationInviteCreated{}, err
	}
	invitedBy := strings.TrimSpace(req.InvitedBy)
	if invitedBy == "" {
		return authflow.AccountRegistrationInviteCreated{}, iam.ErrInvalidInvite
	}

	// #147 register+join: an invite OPTIONALLY carries a group role it ALSO grants on
	// consume. The two halves authorize differently:
	//   - plain registration invite (no role) -> root:users:invite (general onboarding).
	//   - role-carrying invite -> that group's members:manage no-escalation ONLY (the
	//     same mint gate as CreateGroupInviteLink). A member-manager may attach a
	//     registration credential scoped to THIS invite without gaining general
	//     root:users:invite authority.
	group := iam.GroupBySlug(req.Persona, req.InstanceSlug)
	persona := group.Persona()
	role := iam.Role(strings.ToLower(strings.TrimSpace(string(req.Role))))
	carriesRole := persona != "" && role != ""

	var groupID *string
	if carriesRole {
		if !s.externalInvitesEnabled() {
			return authflow.AccountRegistrationInviteCreated{}, iam.ErrExternalInvitesDisabled
		}
		st := s.groupStore()
		sch := s.groupSchemaOrDefault()
		if !s.validRoleForPersona(sch, persona, role) {
			return authflow.AccountRegistrationInviteCreated{}, fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
		}
		gid, err := s.resolveGroupID(ctx, st, group)
		if err != nil {
			return authflow.AccountRegistrationInviteCreated{}, err
		}
		groupID = &gid
	} else if requireRootInvitePermission {
		ok, err := s.Can(ctx, iam.UserSubject(invitedBy), iam.RootGroup(), iam.PermRootUsersInvite)
		if err != nil {
			return authflow.AccountRegistrationInviteCreated{}, err
		}
		if !ok {
			return authflow.AccountRegistrationInviteCreated{}, iam.ErrInsufficientRoleAuthority
		}
	}

	ttl := req.ExpiresIn
	if ttl <= 0 {
		ttl = defaultAccountRegistrationInviteTTL
	}
	expiresAt := time.Now().UTC().Add(ttl)
	code := secret.RandB64(32)
	codeHash := sha256Hex(code)
	var roleParam *iam.Role
	if carriesRole {
		roleParam = &role
	}
	var id string
	insert := func(q db.DBTX) error {
		return q.QueryRow(ctx,
			`INSERT INTO account_registration_invites (email, invited_by, code_hash, expires_at, permission_group_id, role)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6)
		 RETURNING id::text`,
			email, invitedBy, codeHash, expiresAt, groupID, roleParam).Scan(&id)

	}
	var err error
	if groupID != nil {
		err = s.withLockedGroup(ctx, *groupID, func(st *permissionGroupStore) error {
			g := groupTarget{ID: *groupID, Persona: persona}
			if err := s.requireRoleGrant(ctx, st, iam.UserActor(invitedBy), g, iam.PermMembersManage(persona), role); err != nil {
				return err
			}
			return insert(st.q)
		})
	} else {
		err = insert(s.pg)
	}
	if err != nil {
		return authflow.AccountRegistrationInviteCreated{}, err
	}
	created := authflow.AccountRegistrationInviteCreated{
		ID:        id,
		Code:      code,
		URL:       s.accountRegistrationInviteURL(code),
		Email:     email,
		ExpiresAt: expiresAt,
	}
	if carriesRole {
		created.Persona = persona
		created.InstanceSlug = group.Slug()
		created.Role = role
	}
	s.sendAccountRegistrationInviteEmail(ctx, email, created.URL)
	return created, nil
}

func (s *engine) sendAccountRegistrationInviteEmail(ctx context.Context, email, inviteURL string) {
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

func (s *engine) hasValidAccountRegistrationInvite(ctx context.Context, email string) (bool, error) {
	// #147 FINAL: the stranger invite is UNBOUND — the single-use code is the
	// credential, not the address it was delivered to. We check only that a valid,
	// unconsumed, unexpired code is presented; `email` (the registrant's chosen
	// address) is irrelevant to authorization. Whoever holds the link may register.
	token := accountRegistrationInviteTokenFromContext(ctx)
	if token == "" || s.pg == nil {
		return false, nil
	}
	_ = email
	q := s.pg
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM account_registration_invites
		   WHERE code_hash = $1 AND revoked_at IS NULL
		     AND consumed_at IS NULL AND expires_at > now()
		 )`,
		sha256Hex(token)).Scan(&exists)
	return exists, err
}

type registrationInvite struct {
	ID      string
	GroupID *string
	Role    *iam.Role
	Persona *iam.Persona
}

func (s *engine) lockRegistrationInvite(ctx context.Context, tx pgx.Tx, token string) (*registrationInvite, error) {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	if err != nil || mode == iam.RegistrationModeClosed {
		return nil, iam.ErrRegistrationDisabled
	}
	token = strings.TrimSpace(token)
	if token == "" {
		if mode == iam.RegistrationModeInviteOnly {
			return nil, iam.ErrRegistrationDisabled
		}
		return nil, nil
	}
	q := tx
	if err := s.lockAuthority(ctx, q); err != nil {
		return nil, err
	}
	var groupID *string
	err = q.QueryRow(ctx, `SELECT permission_group_id::text FROM account_registration_invites WHERE code_hash=$1 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>now()`, sha256Hex(token)).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrAccountRegistrationInviteNotFound
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
	err = tx.QueryRow(ctx, `SELECT i.id::text,i.permission_group_id::text,i.role,g.persona
FROM account_registration_invites i LEFT JOIN permission_groups g ON g.id=i.permission_group_id
WHERE i.code_hash=$1 AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at>now()
AND i.permission_group_id IS NOT DISTINCT FROM $2::uuid
FOR UPDATE OF i`, sha256Hex(token), groupID).Scan(&invite.ID, &invite.GroupID, &invite.Role, &invite.Persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

func (s *engine) applyRegistrationInvite(ctx context.Context, tx pgx.Tx, invite *registrationInvite, userID string) error {
	if invite == nil {
		return nil
	}
	q := tx
	if _, err := q.Exec(ctx, `UPDATE account_registration_invites SET consumed_at=now(),consumed_by=$2::uuid,updated_at=now() WHERE id=$1::uuid`, invite.ID, userID); err != nil {
		return err
	}
	if invite.GroupID != nil && invite.Role != nil {
		var persona iam.Persona
		if invite.Persona != nil {
			persona = *invite.Persona
		}
		return s.assignInvitedRole(ctx, newPermissionGroupStore(q), *invite.GroupID, persona, userID, *invite.Role)
	}
	return nil
}

func (s *engine) consumeAccountRegistrationInvite(ctx context.Context, _ string, userID string) error {
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
