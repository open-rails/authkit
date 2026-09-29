package engine

// Invite links (#134/#147): a high-entropy, unbound, single-use code for a
// group role. A signed-in user who redeems it gets the role; possession of the
// link is the credential. The code is returned once; only its sha256 is
// stored. Minting needs invited self-registration (externalInvitesEnabled): a
// stranger can join only if they can obtain an account. Issuance follows rule
// CRED (credential_issuers.go).

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	defaultGroupInviteTTL = 72 * time.Hour
	// maxGroupInviteTTL caps a link's lifetime (#247): a longer request is
	// clamped, never rejected, bounding a leaked or forgotten link.
	maxGroupInviteTTL = 30 * 24 * time.Hour
)

// externalInvitesEnabled reports whether invite LINKS may be minted. They make
// sense only when AuthKit permits invited self-registration: open (anyone may
// sign up) or invite_only (sign up ONLY via an invite). Under closed an invited
// stranger has no way to obtain an account, so the capability is OFF (an admin
// assigns roles directly via the members endpoint instead).
func (s *Engine) externalInvitesEnabled() bool {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	if err != nil {
		return false
	}
	return mode == iam.RegistrationModeOpen || mode == iam.RegistrationModeInviteOnly
}

// inviteURL builds the host-facing accept-invite link: BaseURL + the configured
// FrontendInvitePath + ?code=. The SPA reads the code and POSTs it to redeem.
func (s *Engine) inviteURL(code string) string {
	q := url.Values{}
	q.Set("code", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

// requireIssuableRole refuses a role that the group cannot hand out: unknown,
// or custom while the persona has custom roles off.
func (s *Engine) requireIssuableRole(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role) ([]string, error) {
	if err := s.requireDefinedGroupRole(ctx, st, g.ID, g.Persona, role); err != nil {
		return nil, err
	}
	return s.roleGrants(ctx, st, g, role)
}

// CreateInviteLink mints a single-use link granting l.Role in ref:
// CAP(<p>:members:manage) plus COVER(role). Only a user or the system issues
// credentials. The code is returned once.
func (s *Engine) CreateInviteLink(ctx context.Context, a iam.Actor, ref iam.GroupRef, l iam.NewInviteLink) (iam.InviteLinkCreated, error) {
	creator, err := credentialIssuer(a)
	if err != nil {
		return iam.InviteLinkCreated{}, err
	}
	if !s.externalInvitesEnabled() {
		return iam.InviteLinkCreated{}, iam.ErrExternalInvitesDisabled
	}
	role := l.Role
	if role.IsZero() {
		return iam.InviteLinkCreated{}, errmodel.ErrInvalidInvite
	}
	ttl := l.ExpiresIn
	if ttl <= 0 {
		ttl = defaultGroupInviteTTL
	}
	out := iam.InviteLinkCreated{Code: secret.RandB64(32), ExpiresAt: time.Now().UTC().Add(min(ttl, maxGroupInviteTTL))}
	err = s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if _, err := s.requireIssuableRole(ctx, st, g, role); err != nil {
			return err
		}
		if err := s.requireRoleGrant(ctx, st, a, g, iam.PermMembersManage(g.Persona), role); err != nil {
			return err
		}
		return st.q.QueryRow(ctx, `INSERT INTO group_invite_links(permission_group_id,role,invited_by,code_hash,expires_at)
 VALUES($1::uuid,$2,$3::uuid,$4,$5) RETURNING id::text`, g.ID, role.Name(), nullable(creator), sha256Hex(out.Code), out.ExpiresAt).Scan(&out.ID)
	})
	if err != nil {
		return iam.InviteLinkCreated{}, err
	}
	out.URL = s.inviteURL(out.Code)
	return out, nil
}

// InviteLinks lists the group's links, newest first, active or not. Never the
// code or its hash.
func (s *Engine) InviteLinks(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.InviteLink], error) {
	if err := s.requirePG(); err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	after, err := idCursor(p)
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	rows, err := st.q.Query(ctx, `SELECT id::text, role, COALESCE(invited_by::text,''), created_at, expires_at, redeemed_at, revoked_at
 FROM group_invite_links WHERE permission_group_id=$1::uuid AND ($2::uuid IS NULL OR id<$2::uuid)
 ORDER BY id DESC LIMIT $3`, g.ID, after, p.PageLimit()+1)
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	links, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (iam.InviteLink, error) {
		var l iam.InviteLink
		err := row.Scan(&l.ID, scanRole(&l.Role, g.Persona), &l.InvitedBy, &l.CreatedAt, &l.ExpiresAt, &l.RedeemedAt, &l.RevokedAt)
		return l, err
	})
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	return idPage(links, p.PageLimit(), func(l iam.InviteLink) string { return l.ID }), nil
}

// RevokeInviteLink revokes the group's live link: CAP(<p>:members:manage) plus
// COVER of the link's role. ErrInviteLinkNotFound when none matches.
func (s *Engine) RevokeInviteLink(ctx context.Context, a iam.Actor, ref iam.GroupRef, linkID string) error {
	if err := requireActor(a); err != nil {
		return err
	}
	linkID = strings.TrimSpace(linkID)
	return s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !isUUID(linkID) {
			return iam.ErrInviteLinkNotFound
		}
		var role iam.Role
		err := st.q.QueryRow(ctx, `SELECT role FROM group_invite_links WHERE id=$1::uuid AND permission_group_id=$2::uuid AND revoked_at IS NULL FOR UPDATE`, linkID, g.ID).Scan(scanRole(&role, g.Persona))
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInviteLinkNotFound
		}
		if err != nil {
			return err
		}
		if err := s.requireCredentialRevoke(ctx, st, a, g, iam.PermMembersManage(g.Persona), role); err != nil {
			return err
		}
		_, err = st.q.Exec(ctx, `UPDATE group_invite_links SET revoked_at=now(), updated_at=now() WHERE id=$1::uuid`, linkID)
		return err
	})
}

// RedeemInviteLink redeems code for the signed-in user a: the link must be
// live (not revoked, expired or used) and its issuer live, and the redeemer
// live. The role is assigned in the same transaction and the link consumed.
// Idempotent: a redeemer already holding the role succeeds without using it.
// code may also be a role-carrying account invitation (an add by email): only
// the account that has verified the invited address accepts it.
func (s *Engine) RedeemInviteLink(ctx context.Context, a iam.Actor, code string) (authflow.InviteRedemption, error) {
	var out authflow.InviteRedemption
	code = strings.TrimSpace(code)
	if a.Kind() != iam.ActorUser || !isUUID(a.ID()) {
		return out, iam.ErrInsufficientAuthority
	}
	if code == "" {
		return out, errmodel.ErrInvalidInvite
	}
	redeemer := iam.UserSubject(a.ID())
	codeHash := sha256Hex(code)
	err := s.withAuthorityMutation(ctx, a, func(st *permissionGroupStore) error {
		var groupID string
		err := st.q.QueryRow(ctx, `SELECT permission_group_id::text FROM group_invite_links WHERE code_hash=$1`, codeHash).Scan(&groupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.acceptAccountInvite(ctx, st, redeemer, codeHash, &out)
		}
		if err != nil {
			return err
		}
		if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
			return err
		}
		var linkID, role string
		var redeemedAt, expiresAt, revokedAt *time.Time
		var issuerOK bool
		err = st.q.QueryRow(ctx, `SELECT l.id::text, g.id::text, g.persona, l.role, l.redeemed_at, l.expires_at, l.revoked_at, `+issuerLive("l.invited_by")+`
 FROM group_invite_links l JOIN permission_groups g ON g.id=l.permission_group_id
 WHERE l.code_hash=$1 AND l.permission_group_id=$2::uuid
 FOR UPDATE OF l`, codeHash, groupID).Scan(&linkID, &out.GroupID, scanPersona(&out.Persona), &role, &redeemedAt, &expiresAt, &revokedAt, &issuerOK)
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInviteLinkNotFound
		}
		if err != nil {
			return err
		}
		out.Role = ident.Role(out.Persona, role)
		if revokedAt != nil || !issuerOK {
			return errmodel.ErrInviteLinkRevoked
		}
		if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
			return errmodel.ErrInviteLinkExpired
		}
		live, err := subjectUsable(ctx, st.q, redeemer)
		if err != nil {
			return err
		}
		if !live {
			return iam.ErrInsufficientAuthority
		}
		already, err := subjectHasRole(ctx, st.q, groupID, redeemer.ID, out.Role)
		if err != nil || already {
			return err
		}
		if redeemedAt != nil {
			return iam.ErrInviteLinkNotFound
		}
		if err := s.assignInvitedRole(ctx, st, groupID, out.Persona, redeemer.ID, out.Role); err != nil {
			return err
		}
		_, err = st.q.Exec(ctx, `UPDATE group_invite_links SET redeemed_at=now(), updated_at=now() WHERE id=$1::uuid`, linkID)
		return err
	})
	if err != nil {
		return authflow.InviteRedemption{}, err
	}
	return out, nil
}

// acceptAccountInvite accepts a role-carrying account invitation for an
// existing account: the redeemer's verified email must be the invited address,
// so the role lands only with the consent of whoever proved it. Anything else
// is ErrInviteLinkNotFound, never a hint about the invitation.
func (s *Engine) acceptAccountInvite(ctx context.Context, st *permissionGroupStore, redeemer iam.Subject, codeHash string, out *authflow.InviteRedemption) error {
	var groupID string
	err := st.q.QueryRow(ctx, `SELECT permission_group_id::text FROM account_registration_invites WHERE code_hash=$1 AND permission_group_id IS NOT NULL`, codeHash).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrInviteLinkNotFound
	}
	if err != nil {
		return err
	}
	if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
		return err
	}
	var inviteID, role string
	var consumedAt, revokedAt *time.Time
	var expiresAt time.Time
	var issuerOK, addressed bool
	err = st.q.QueryRow(ctx, `SELECT i.id::text, g.id::text, g.persona, COALESCE(i.role,''), i.consumed_at, i.expires_at, i.revoked_at, `+issuerLive("i.invited_by")+`,
       EXISTS(SELECT 1 FROM users u WHERE u.id=$3::uuid AND lower(u.email::text)=lower(i.email::text) AND u.email_verified)
 FROM account_registration_invites i JOIN permission_groups g ON g.id=i.permission_group_id AND g.deleted_at IS NULL
 WHERE i.code_hash=$1 AND i.permission_group_id=$2::uuid
 FOR UPDATE OF i`, codeHash, groupID, redeemer.ID).Scan(&inviteID, &out.GroupID, scanPersona(&out.Persona), &role, &consumedAt, &expiresAt, &revokedAt, &issuerOK, &addressed)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !addressed {
		return iam.ErrInviteLinkNotFound
	}
	if err != nil {
		return err
	}
	out.Role = ident.Role(out.Persona, role)
	if revokedAt != nil || !issuerOK {
		return errmodel.ErrInviteLinkRevoked
	}
	if !expiresAt.After(time.Now().UTC()) {
		return errmodel.ErrInviteLinkExpired
	}
	live, err := subjectUsable(ctx, st.q, redeemer)
	if err != nil {
		return err
	}
	if !live {
		return iam.ErrInsufficientAuthority
	}
	already, err := subjectHasRole(ctx, st.q, groupID, redeemer.ID, out.Role)
	if err != nil || already {
		return err
	}
	if consumedAt != nil {
		return iam.ErrInviteLinkNotFound
	}
	if err := s.assignInvitedRole(ctx, st, groupID, out.Persona, redeemer.ID, out.Role); err != nil {
		return err
	}
	_, err = st.q.Exec(ctx, `UPDATE account_registration_invites SET consumed_at=now(), consumed_by=$2::uuid, updated_at=now() WHERE id=$1::uuid`, inviteID, redeemer.ID)
	return err
}

// subjectHasRole reports whether the user already holds role in the group.
func subjectHasRole(ctx context.Context, q db.DBTX, groupID, userID string, role iam.Role) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM group_user_roles
		   WHERE permission_group_id = $1::uuid AND user_id = $2::uuid AND role = $3)`,
		groupID, userID, role.Name()).Scan(&exists)
	return exists, err
}
