package engine

// Invite LINKS (#134/#147): the human "bring a stranger into a permission-group"
// flow. A high-entropy, unbound, single-use code is minted for a group+role; when
// a logged-in user REDEEMS it, that role is assigned to them. Possession of the
// link is the credential.
// Redeeming IS joining; there is no separate accept/decline step (adding an
// existing user directly is the members endpoint, which needs no confirmation).
//
// The plaintext code is returned to the minter ONCE; only its sha256 hex is
// stored. Group ids stay INTERNAL; callers address the owning group by
// (persona, instance_slug). Minting is gated on the registration mode permitting
// invited self-registration (see externalInvitesEnabled) — an invited stranger
// can only join if they can obtain an account.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	defaultGroupInviteTTL = 72 * time.Hour
	// maxGroupInviteTTL is the hard ceiling on an invite link's requested
	// lifetime (#247, Paul's decision): a mint requesting longer is CLAMPED down
	// to now+30d, never rejected — mirrors APIKeysConfig.MaxTTL's capping
	// semantics. Possession of the link is the credential, so an unbounded TTL
	// is an unbounded-lifetime credential; 30d bounds the blast radius of a
	// leaked/forgotten link without breaking the common case (the default stays
	// 72h).
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

// CreateGroupInviteLink mints an unbound single-use invite link. Returns the
// plaintext code ONCE.
func (s *Engine) CreateGroupInviteLink(ctx context.Context, req iam.CreateGroupInviteLinkRequest) (iam.GroupInviteLinkCreated, error) {
	if err := s.requirePG(); err != nil {
		return iam.GroupInviteLinkCreated{}, err
	}
	if !s.externalInvitesEnabled() {
		return iam.GroupInviteLinkCreated{}, iam.ErrExternalInvitesDisabled
	}
	role := iam.Role(strings.ToLower(strings.TrimSpace(string(req.Role))))
	invitedBy := strings.TrimSpace(req.InvitedBy)
	if role == "" || invitedBy == "" {
		return iam.GroupInviteLinkCreated{}, iam.ErrInvalidInvite
	}
	group := iam.GroupBySlug(req.Persona, req.InstanceSlug)
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, group.Persona(), role) {
		return iam.GroupInviteLinkCreated{}, fmt.Errorf("role %q is not assignable in a %q group: %w", role, group.Persona(), iam.ErrRoleNotAssignable)
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return iam.GroupInviteLinkCreated{}, err
	}
	ttl := req.ExpiresIn
	if ttl <= 0 {
		ttl = defaultGroupInviteTTL
	}
	if ttl > maxGroupInviteTTL {
		ttl = maxGroupInviteTTL
	}
	expiresAt := time.Now().UTC().Add(ttl)
	code := secret.RandB64(32)
	var id string
	err = s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		g := groupTarget{ID: gid, Persona: group.Persona()}
		if err := s.requireRoleGrant(ctx, st, iam.UserActor(invitedBy), g, iam.PermMembersManage(g.Persona), role); err != nil {
			return err
		}
		return st.q.QueryRow(ctx, `INSERT INTO group_invite_links(permission_group_id,role,invited_by,code_hash,expires_at)
  VALUES($1::uuid,$2,$3::uuid,$4,$5) RETURNING id::text`, gid, role, invitedBy, sha256Hex(code), expiresAt).Scan(&id)
	})
	if err != nil {
		return iam.GroupInviteLinkCreated{}, err
	}
	return iam.GroupInviteLinkCreated{ID: id, Code: code, URL: s.inviteURL(code)}, nil
}

// ListGroupInviteLinks lists the group's invite links (active and inactive),
// newest first. Never returns the code or its hash.
func (s *Engine) ListGroupInviteLinks(ctx context.Context, group iam.GroupRef) ([]iam.GroupInviteLink, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return nil, err
	}
	q := s.pg
	rows, err := q.Query(ctx,
		`SELECT id::text, permission_group_id::text, role, invited_by::text,
		        redeemed_at, expires_at, revoked_at, created_at, updated_at
		 FROM group_invite_links
		 WHERE permission_group_id = $1::uuid
		 ORDER BY created_at DESC`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]iam.GroupInviteLink, 0)
	for rows.Next() {
		var l iam.GroupInviteLink
		if err := rows.Scan(&l.ID, &l.PermissionGroupID, &l.Role, &l.InvitedBy,
			&l.RedeemedAt, &l.ExpiresAt, &l.RevokedAt, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// RevokeGroupInviteLink revokes a link by id, scoped to the group addressed by
// (persona, instanceSlug) so a manager cannot revoke another group's link.
func (s *Engine) RevokeGroupInviteLink(ctx context.Context, group iam.GroupRef, linkID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	linkID = strings.TrimSpace(linkID)
	if linkID == "" {
		return iam.ErrInvalidInvite
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return err
	}
	q := s.pg
	tag, err := q.Exec(ctx,
		`UPDATE group_invite_links SET revoked_at = now(), updated_at = now()
		 WHERE id = $1::uuid AND permission_group_id = $2::uuid AND revoked_at IS NULL`,
		linkID, gid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return iam.ErrInviteLinkNotFound
	}
	return nil
}

// RevokeGroupInviteLinkForActor is the runtime revoke: the actor must be able
// to mint the link's role, so a bounded manager cannot revoke a link of a role
// above their own.
func (s *Engine) RevokeGroupInviteLinkForActor(ctx context.Context, actor iam.Actor, group iam.GroupRef, linkID string) error {
	if err := requireActor(actor); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	linkID = strings.TrimSpace(linkID)
	if linkID == "" {
		return iam.ErrInvalidInvite
	}
	g, err := s.resolveGroup(ctx, s.groupStore(), group)
	if err != nil {
		return err
	}
	gid := g.ID
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		var role iam.Role
		err := st.q.QueryRow(ctx, `SELECT role FROM group_invite_links WHERE id=$1::uuid AND permission_group_id=$2::uuid AND revoked_at IS NULL FOR UPDATE`, linkID, gid).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInviteLinkNotFound
		}
		if err != nil {
			return err
		}
		if err := s.requireRoleGrant(ctx, st, actor, g, iam.PermMembersManage(g.Persona), role); err != nil {
			return err
		}
		_, err = st.q.Exec(ctx, `UPDATE group_invite_links SET revoked_at=now(), updated_at=now() WHERE id=$1::uuid`, linkID)
		return err
	})
}

// RedeemGroupInviteLink redeems code on behalf of the authenticated redeemerUserID:
// it validates the link (live, not expired/revoked, unredeemed), assigns the role
// in the same transaction, and stamps redeemed_at. Idempotent: if the redeemer
// already holds that role, it succeeds without consuming the link.
func (s *Engine) RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (authflow.RedeemGroupInviteLinkResult, error) {
	var zero authflow.RedeemGroupInviteLinkResult
	if err := s.requirePG(); err != nil {
		return zero, err
	}
	code = strings.TrimSpace(code)
	redeemerUserID = strings.TrimSpace(redeemerUserID)
	if code == "" || redeemerUserID == "" {
		return zero, iam.ErrInvalidInvite
	}
	codeHash := sha256Hex(code)

	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return zero, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := tx
	if err := s.lockAuthority(ctx, q); err != nil {
		return zero, err
	}

	var groupID string
	err = q.QueryRow(ctx, `SELECT permission_group_id::text FROM group_invite_links WHERE code_hash=$1`, codeHash).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, iam.ErrInviteLinkNotFound
	}
	if err != nil {
		return zero, err
	}
	if err := lockPermissionGroup(ctx, q, groupID); err != nil {
		return zero, err
	}
	var linkID, instanceSlug string
	var persona iam.Persona
	var role iam.Role
	var redeemedAt, expiresAt, revokedAt *time.Time
	err = q.QueryRow(ctx,
		`SELECT l.id::text, l.permission_group_id::text, g.persona, COALESCE(g.instance_slug,''), l.role,
		        l.redeemed_at, l.expires_at, l.revoked_at
		 FROM group_invite_links l
		 JOIN permission_groups g ON g.id = l.permission_group_id
		 WHERE l.code_hash = $1 AND l.permission_group_id=$2::uuid
		 FOR UPDATE OF l`,
		codeHash, groupID).Scan(&linkID, &groupID, &persona, &instanceSlug, &role, &redeemedAt, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, iam.ErrInviteLinkNotFound
	}
	if err != nil {
		return zero, err
	}
	if revokedAt != nil {
		return zero, iam.ErrInviteLinkRevoked
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return zero, iam.ErrInviteLinkExpired
	}
	// Idempotency: already holds this role => success, no use consumed.
	already, err := subjectHasRole(ctx, q, groupID, redeemerUserID, role)
	if err != nil {
		return zero, err
	}
	if !already {
		if redeemedAt != nil {
			return zero, iam.ErrInviteLinkNotFound
		}
		if err := s.assignInvitedRole(ctx, newPermissionGroupStore(q), groupID, persona, redeemerUserID, role); err != nil {
			return zero, err
		}
		if _, err := q.Exec(ctx,
			`UPDATE group_invite_links SET redeemed_at = now(), updated_at = now() WHERE id = $1::uuid`,
			linkID); err != nil {
			return zero, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	return authflow.RedeemGroupInviteLinkResult{Persona: persona, InstanceSlug: instanceSlug, Role: role}, nil
}

// subjectHasRole reports whether the user already holds role in the group.
func subjectHasRole(ctx context.Context, q db.DBTX, groupID, userID string, role iam.Role) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM group_user_roles
		   WHERE permission_group_id = $1::uuid AND user_id = $2::uuid AND role = $3)`,
		groupID, userID, role).Scan(&exists)
	return exists, err
}
