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
	out := iam.AccountInviteCreated{Code: secret.RandB64(32), Email: email, ExpiresAt: time.Now().UTC().Add(ttl)}
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
		return st.q.QueryRow(ctx, `INSERT INTO account_registration_invites (email, invited_by, code_hash, expires_at, permission_group_id, role)
 VALUES ($1, $2::uuid, $3, $4, $5, $6) RETURNING id::text`,
			email, nullable(creator), sha256Hex(out.Code), out.ExpiresAt, groupID, roleParam).Scan(&out.ID)
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
	q := s.pg
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM account_registration_invites i
		   WHERE i.code_hash = $1 AND i.revoked_at IS NULL
		     AND i.consumed_at IS NULL AND i.expires_at > now() AND `+issuerLive("i.invited_by")+`
		 )`,
		sha256Hex(token)).Scan(&exists)
	return exists, err
}

type registrationInvite struct {
	ID      string
	GroupID *string
	Role    *string
	Persona *string
}

func (s *Engine) lockRegistrationInvite(ctx context.Context, tx pgx.Tx, token string) (*registrationInvite, error) {
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
	q := tx
	if err := s.lockAuthority(ctx, q); err != nil {
		return nil, err
	}
	var groupID *string
	err = q.QueryRow(ctx, `SELECT i.permission_group_id::text FROM account_registration_invites i WHERE i.code_hash=$1 AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at>now() AND `+issuerLive("i.invited_by"), sha256Hex(token)).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errmodel.ErrAccountRegistrationInviteNotFound
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
WHERE i.code_hash=$1 AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at>now() AND `+issuerLive("i.invited_by")+`
AND i.permission_group_id IS NOT DISTINCT FROM $2::uuid
FOR UPDATE OF i`, sha256Hex(token), groupID).Scan(&invite.ID, &invite.GroupID, &invite.Role, &invite.Persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errmodel.ErrAccountRegistrationInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

func (s *Engine) applyRegistrationInvite(ctx context.Context, tx pgx.Tx, invite *registrationInvite, userID string) error {
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
			persona = ident.Persona(*invite.Persona)
		}
		st := s.groupStoreFor(tx)
		st.actor = iam.UserActor(userID)
		return s.assignInvitedRole(ctx, st, *invite.GroupID, persona, userID, ident.Role(persona, *invite.Role))
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
