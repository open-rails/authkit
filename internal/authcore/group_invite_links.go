package authcore

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
	authkit "github.com/open-rails/authkit"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

const defaultGroupInviteTTL = 72 * time.Hour

var (
	// ErrInviteLinkNotFound indicates no invite link matched the code/lookup.
	ErrInviteLinkNotFound = authkit.ErrInviteLinkNotFound
	// ErrInviteLinkExpired indicates the link's expires_at has passed.
	ErrInviteLinkExpired = authkit.ErrInviteLinkExpired
	// ErrInviteLinkRevoked indicates the link was revoked by a manager.
	ErrInviteLinkRevoked = authkit.ErrInviteLinkRevoked
	// ErrExternalInvitesDisabled indicates invite links are off because the
	// deployment's registration mode does not permit invited self-registration.
	ErrExternalInvitesDisabled = authkit.ErrExternalInvitesDisabled
)

// GroupInviteLink is the non-secret view of an invite link (never carries the
// code or its hash).
type GroupInviteLink = authkit.GroupInviteLink

// CreateGroupInviteLinkRequest mints an invite link for the group addressed by
// (Persona, InstanceSlug) granting Role. ExpiresIn overrides the default lifetime.
type CreateGroupInviteLinkRequest = authkit.CreateGroupInviteLinkRequest

// GroupInviteLinkCreated is the mint result: the plaintext Code (shown ONCE) and
// the ready-to-send URL.
type GroupInviteLinkCreated = authkit.GroupInviteLinkCreated

// externalInvitesEnabled reports whether invite LINKS may be minted. They make
// sense only when AuthKit permits invited self-registration: open (anyone may
// sign up) or invite_only (sign up ONLY via an invite). Under closed an invited
// stranger has no way to obtain an account, so the capability is OFF (an admin
// assigns roles directly via the members endpoint instead).
func (s *Service) externalInvitesEnabled() bool {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	if err != nil {
		return false
	}
	return mode == RegistrationModeOpen || mode == RegistrationModeInviteOnly
}

// ExternalInvitesEnabled exposes the registration-mode gate for HTTP adapters
// (so a closed-registration deployment can omit/zero the invite-link routes).
func (s *Service) ExternalInvitesEnabled() bool { return s.externalInvitesEnabled() }

// inviteURL builds the host-facing accept-invite link: BaseURL + the configured
// FrontendInvitePath + ?code=. The SPA reads the code and POSTs it to redeem.
func (s *Service) inviteURL(code string) string {
	q := url.Values{}
	q.Set("code", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

// CreateGroupInviteLink mints an unbound single-use invite link. Returns the
// plaintext code ONCE.
func (s *Service) CreateGroupInviteLink(ctx context.Context, req CreateGroupInviteLinkRequest) (GroupInviteLinkCreated, error) {
	if err := s.requirePG(); err != nil {
		return GroupInviteLinkCreated{}, err
	}
	if !s.externalInvitesEnabled() {
		return GroupInviteLinkCreated{}, ErrExternalInvitesDisabled
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	invitedBy := strings.TrimSpace(req.InvitedBy)
	if role == "" || invitedBy == "" {
		return GroupInviteLinkCreated{}, errors.New("invalid_invite")
	}
	persona := strings.TrimSpace(req.Persona)
	instanceSlug := strings.TrimSpace(req.InstanceSlug)
	st := s.groupStore()
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, persona, role) {
		return GroupInviteLinkCreated{}, fmt.Errorf("role %q is not assignable in a %q group", role, persona)
	}
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return GroupInviteLinkCreated{}, err
	}
	// AK2-AUTHZ-1: an invite link is a DEFERRED role grant, so the MINT must pass
	// the same no-escalation check every other grant surface uses (member
	// add/role-change via AssignGroupRoleAs, API-key mint via authorizeAPIKeyRoleGrant).
	// The minter (invited_by — the authenticated caller, never request-supplied)
	// must hold members:manage in this group AND already hold every permission the
	// invited role confers; otherwise a holder of only members-management authority
	// could mint (and then redeem) an `owner` invite to escalate. The gate is on
	// MINT because the redeemer is not the granting authority — the redeemer's own
	// grants are irrelevant to what the link is allowed to confer.
	if err := s.authorizeRoleChange(ctx, st, sch, persona, gid, invitedBy, role); err != nil {
		return GroupInviteLinkCreated{}, err
	}

	ttl := req.ExpiresIn
	if ttl <= 0 {
		ttl = defaultGroupInviteTTL
	}
	expiresAt := time.Now().UTC().Add(ttl)

	code := randB64(32)
	codeHash := sha256Hex(code)
	q := db.ForSchema(s.pg, s.dbSchema())
	var id string
	err = q.QueryRow(ctx,
		`INSERT INTO profiles.group_invite_links (permission_group_id, role, invited_by, code_hash, expires_at)
		 VALUES ($1::uuid, $2, $3::uuid, $4, $5)
		 RETURNING id::text`,
		gid, role, invitedBy, codeHash, expiresAt).Scan(&id)
	if err != nil {
		return GroupInviteLinkCreated{}, err
	}
	created := GroupInviteLinkCreated{ID: id, Code: code, URL: s.inviteURL(code)}
	return created, nil
}

// ListGroupInviteLinks lists the group's invite links (active and inactive),
// newest first. Never returns the code or its hash.
func (s *Service) ListGroupInviteLinks(ctx context.Context, persona, instanceSlug string) ([]GroupInviteLink, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(instanceSlug))
	if err != nil {
		return nil, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT id::text, permission_group_id::text, role, invited_by::text,
		        redeemed_at, expires_at, revoked_at, created_at, updated_at
		 FROM profiles.group_invite_links
		 WHERE permission_group_id = $1::uuid
		 ORDER BY created_at DESC`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GroupInviteLink, 0)
	for rows.Next() {
		var l GroupInviteLink
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
func (s *Service) RevokeGroupInviteLink(ctx context.Context, persona, instanceSlug, linkID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	linkID = strings.TrimSpace(linkID)
	if linkID == "" {
		return errors.New("invalid_invite")
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(instanceSlug))
	if err != nil {
		return err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.group_invite_links SET revoked_at = now(), updated_at = now()
		 WHERE id = $1::uuid AND permission_group_id = $2::uuid AND revoked_at IS NULL`,
		linkID, gid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteLinkNotFound
	}
	return nil
}

// RedeemGroupInviteLinkResult reports which (persona, instance, role) a redemption
// granted, so the caller/SPA can route the user to the right place.
type RedeemGroupInviteLinkResult = authkit.RedeemGroupInviteLinkResult

// RedeemGroupInviteLink redeems code on behalf of the authenticated redeemerUserID:
// it validates the link (live, not expired/revoked, unredeemed), assigns the role
// in the same transaction, and stamps redeemed_at. Idempotent: if the redeemer
// already holds that role, it succeeds without consuming the link.
func (s *Service) RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (RedeemGroupInviteLinkResult, error) {
	var zero RedeemGroupInviteLinkResult
	if err := s.requirePG(); err != nil {
		return zero, err
	}
	code = strings.TrimSpace(code)
	redeemerUserID = strings.TrimSpace(redeemerUserID)
	if code == "" || redeemerUserID == "" {
		return zero, errors.New("invalid_invite")
	}
	codeHash := sha256Hex(code)

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return zero, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())

	var linkID, groupID, persona, instanceSlug, role string
	var redeemedAt, expiresAt, revokedAt *time.Time
	err = q.QueryRow(ctx,
		`SELECT l.id::text, l.permission_group_id::text, g.persona, COALESCE(g.instance_slug,''), l.role,
		        l.redeemed_at, l.expires_at, l.revoked_at
		 FROM profiles.group_invite_links l
		 JOIN profiles.permission_groups g ON g.id = l.permission_group_id
		 WHERE l.code_hash = $1
		 FOR UPDATE OF l`,
		codeHash).Scan(&linkID, &groupID, &persona, &instanceSlug, &role, &redeemedAt, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, ErrInviteLinkNotFound
	}
	if err != nil {
		return zero, err
	}
	if revokedAt != nil {
		return zero, ErrInviteLinkRevoked
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return zero, ErrInviteLinkExpired
	}
	// Idempotency: already holds this role => success, no use consumed.
	already, err := subjectHasRole(ctx, q, groupID, redeemerUserID, role)
	if err != nil {
		return zero, err
	}
	if !already {
		if redeemedAt != nil {
			return zero, ErrInviteLinkNotFound
		}
		if err := s.requireMFAForRoleAssignment(ctx, q, persona, redeemerUserID, SubjectKindUser, role); err != nil {
			return zero, err
		}
		if err := NewPermissionGroupStore(q).AssignRole(ctx, groupID, redeemerUserID, SubjectKindUser, role); err != nil {
			return zero, err
		}
		if _, err := q.Exec(ctx,
			`UPDATE profiles.group_invite_links SET redeemed_at = now(), updated_at = now() WHERE id = $1::uuid`,
			linkID); err != nil {
			return zero, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	return RedeemGroupInviteLinkResult{Persona: persona, InstanceSlug: instanceSlug, Role: role}, nil
}

// subjectHasRole reports whether the user already holds role in the group.
func subjectHasRole(ctx context.Context, q db.DBTX, groupID, userID, role string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM profiles.group_user_roles
		   WHERE permission_group_id = $1::uuid AND user_id = $2::uuid AND role = $3 AND deleted_at IS NULL)`,
		groupID, userID, role).Scan(&exists)
	return exists, err
}
