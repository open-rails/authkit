package authcore

// Invite LINKS (#134): the human "bring a (possibly not-yet-registered) person
// into a permission-group" flow. A high-entropy code is minted for a group+role;
// when a logged-in user REDEEMS it, that role is assigned to them. Two shapes,
// one primitive:
//   - email-bound  (Email set, MaxUses defaults to 1): only that verified address
//     may redeem — "email a specific person".
//   - shareable    (Email empty, MaxUses NULL = unlimited or a cap): anyone with
//     the code may redeem — "post the link in a channel".
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

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// Per-kind default link lifetimes (overridable per-link via ExpiresIn).
const (
	defaultEmailInviteTTL     = 7 * 24 * time.Hour // "email a specific person"
	defaultShareableInviteTTL = 24 * time.Hour     // "post the link in a channel"
)

var (
	// ErrInviteLinkNotFound indicates no invite link matched the code/lookup.
	ErrInviteLinkNotFound = errors.New("group_invite_link_not_found")
	// ErrInviteLinkExpired indicates the link's expires_at has passed.
	ErrInviteLinkExpired = errors.New("group_invite_link_expired")
	// ErrInviteLinkExhausted indicates the link hit its max_uses cap.
	ErrInviteLinkExhausted = errors.New("group_invite_link_exhausted")
	// ErrInviteLinkRevoked indicates the link was revoked by a manager.
	ErrInviteLinkRevoked = errors.New("group_invite_link_revoked")
	// ErrInviteEmailMismatch indicates an email-bound link was redeemed by a user
	// whose verified email does not match the bound address.
	ErrInviteEmailMismatch = errors.New("group_invite_email_mismatch")
	// ErrExternalInvitesDisabled indicates invite links are off because the
	// deployment's registration mode does not permit invited self-registration.
	ErrExternalInvitesDisabled = errors.New("external_invites_disabled")
)

// GroupInviteMessage carries the rendered data an email sender needs to deliver a
// permission-group invite. AuthKit builds InviteURL (BaseURL + FrontendInvitePath
// + ?code=); the host supplies transport + branding/copy.
type GroupInviteMessage struct {
	InviteURL    string // the accept-invite link the recipient clicks
	Persona      string // the group's persona (e.g. "merchant")
	InstanceSlug string // which instance (e.g. "acme-store")
	Role         string // the role the invite grants
	Purpose      string // lets senders vary copy without new methods
}

// GroupInviteEmailSender is an OPTIONAL capability on an EmailSender: if the
// configured sender also implements it, AuthKit delivers email-bound invite links
// through it. Senders that don't implement it simply don't get invite emails —
// the minter still receives the code/URL to deliver out-of-band. Optional (not
// folded into EmailSender) because invites are an opt-in feature; a deployment
// that never mints invite links should not be forced to render invite email.
type GroupInviteEmailSender interface {
	SendGroupInvite(ctx context.Context, email string, msg GroupInviteMessage) error
}

// GroupInviteLink is the non-secret view of an invite link (never carries the
// code or its hash).
type GroupInviteLink struct {
	ID                string
	PermissionGroupID string
	Role              string
	InvitedBy         string
	Email             string // "" = shareable (anyone may redeem)
	MaxUses           *int   // nil = unlimited
	Uses              int
	ExpiresAt         *time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CreateGroupInviteLinkRequest mints an invite link for the group addressed by
// (Persona, InstanceSlug) granting Role. Email set => email-bound (defaults to
// single-use); empty => shareable. MaxUses caps redemptions (nil = unlimited).
// ExpiresIn overrides the per-kind default lifetime.
type CreateGroupInviteLinkRequest struct {
	Persona      string
	InstanceSlug string
	Role         string
	Email        string
	MaxUses      *int
	ExpiresIn    time.Duration
	InvitedBy    string
}

// GroupInviteLinkCreated is the mint result: the plaintext Code (shown ONCE) and
// the ready-to-send URL.
type GroupInviteLinkCreated struct {
	ID   string
	Code string
	URL  string
}

// externalInvitesEnabled reports whether invite LINKS may be minted. They make
// sense only when AuthKit permits invited self-registration: open (anyone may
// sign up) or invite_only (sign up ONLY via an invite). Under
// admin_only/admin_bootstrap_only/manifest_only/closed an invited stranger has no
// way to obtain an account, so the capability is OFF (an admin assigns roles
// directly via the members endpoint instead).
func (o Options) externalInvitesEnabled() bool {
	mode, err := normalizeRegistrationMode(o.NativeUserRegistrationMode)
	if err != nil {
		return false
	}
	return mode == RegistrationModeOpen || mode == RegistrationModeInviteOnly
}

// ExternalInvitesEnabled exposes the registration-mode gate for HTTP adapters
// (so a closed-registration deployment can omit/zero the invite-link routes).
func (s *Service) ExternalInvitesEnabled() bool { return s.opts.externalInvitesEnabled() }

// inviteURL builds the host-facing accept-invite link: BaseURL + the configured
// FrontendInvitePath + ?code=. The SPA reads the code and POSTs it to redeem.
func (s *Service) inviteURL(code string) string {
	q := url.Values{}
	q.Set("code", code)
	return s.authkitURL(s.opts.FrontendInvitePath, q)
}

// CreateGroupInviteLink mints an invite link (and, for email-bound links, emails
// it when the sender supports invite delivery). Returns the plaintext code ONCE.
func (s *Service) CreateGroupInviteLink(ctx context.Context, req CreateGroupInviteLinkRequest) (GroupInviteLinkCreated, error) {
	if err := s.requirePG(); err != nil {
		return GroupInviteLinkCreated{}, err
	}
	if !s.opts.externalInvitesEnabled() {
		return GroupInviteLinkCreated{}, ErrExternalInvitesDisabled
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	invitedBy := strings.TrimSpace(req.InvitedBy)
	if role == "" || invitedBy == "" {
		return GroupInviteLinkCreated{}, errors.New("invalid_invite")
	}
	persona := strings.TrimSpace(req.Persona)
	instanceSlug := strings.TrimSpace(req.InstanceSlug)
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), persona, role) {
		return GroupInviteLinkCreated{}, fmt.Errorf("role %q is not assignable in a %q group", role, persona)
	}
	if req.MaxUses != nil && *req.MaxUses < 1 {
		return GroupInviteLinkCreated{}, errors.New("invalid_max_uses")
	}
	email := ""
	if strings.TrimSpace(req.Email) != "" {
		email = NormalizeEmail(req.Email)
		if err := ValidateEmail(email); err != nil {
			return GroupInviteLinkCreated{}, err
		}
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), persona, instanceSlug)
	if err != nil {
		return GroupInviteLinkCreated{}, err
	}

	ttl := req.ExpiresIn
	if ttl <= 0 {
		ttl = defaultShareableInviteTTL
		if email != "" {
			ttl = defaultEmailInviteTTL
		}
	}
	expiresAt := time.Now().UTC().Add(ttl)
	// Email-bound links default to single-use unless the caller set max_uses.
	maxUses := req.MaxUses
	if email != "" && maxUses == nil {
		one := 1
		maxUses = &one
	}

	code := randB64(32)
	codeHash := sha256Hex(code)
	q := db.ForSchema(s.pg, s.dbSchema())
	var id string
	err = q.QueryRow(ctx,
		`INSERT INTO profiles.group_invite_links (permission_group_id, role, invited_by, code_hash, email, max_uses, expires_at)
		 VALUES ($1::uuid, $2, $3::uuid, $4, NULLIF($5,''), $6, $7)
		 RETURNING id::text`,
		gid, role, invitedBy, codeHash, email, maxUses, expiresAt).Scan(&id)
	if err != nil {
		return GroupInviteLinkCreated{}, err
	}
	created := GroupInviteLinkCreated{ID: id, Code: code, URL: s.inviteURL(code)}

	// Email-bound: AuthKit delivers the link (batteries-included, #131 model).
	// Best-effort — the minter holds the code regardless, so a transient send
	// failure does not undo the mint.
	if email != "" {
		s.sendGroupInviteEmail(ctx, email, persona, instanceSlug, role, created.URL)
	}
	return created, nil
}

func (s *Service) sendGroupInviteEmail(ctx context.Context, email, persona, instanceSlug, role, inviteURL string) {
	if s.email == nil {
		return
	}
	sender, ok := s.email.(GroupInviteEmailSender)
	if !ok {
		return
	}
	msg := GroupInviteMessage{InviteURL: inviteURL, Persona: persona, InstanceSlug: instanceSlug, Role: role, Purpose: "group_invite"}
	_ = s.withSendTimeout(ctx, func(sendCtx context.Context) error {
		return sender.SendGroupInvite(sendCtx, email, msg)
	})
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
		`SELECT id::text, permission_group_id::text, role, invited_by::text, COALESCE(email,''),
		        max_uses, uses, expires_at, revoked_at, created_at, updated_at
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
		if err := rows.Scan(&l.ID, &l.PermissionGroupID, &l.Role, &l.InvitedBy, &l.Email,
			&l.MaxUses, &l.Uses, &l.ExpiresAt, &l.RevokedAt, &l.CreatedAt, &l.UpdatedAt); err != nil {
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
type RedeemGroupInviteLinkResult struct {
	Persona      string
	InstanceSlug string
	Role         string
}

// RedeemGroupInviteLink redeems code on behalf of the authenticated redeemerUserID:
// it validates the link (live, not expired/revoked, within max_uses; for an
// email-bound link the redeemer's verified email must match), assigns the role in
// the same transaction, and increments uses. Idempotent: if the redeemer already
// holds that role, it succeeds WITHOUT consuming a use.
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

	var linkID, groupID, persona, instanceSlug, role, email string
	var maxUses *int
	var uses int
	var expiresAt, revokedAt *time.Time
	err = q.QueryRow(ctx,
		`SELECT l.id::text, l.permission_group_id::text, g.persona, COALESCE(g.instance_slug,''), l.role,
		        COALESCE(l.email,''), l.max_uses, l.uses, l.expires_at, l.revoked_at
		 FROM profiles.group_invite_links l
		 JOIN profiles.permission_groups g ON g.id = l.permission_group_id
		 WHERE l.code_hash = $1 AND g.deleted_at IS NULL
		 FOR UPDATE OF l`,
		codeHash).Scan(&linkID, &groupID, &persona, &instanceSlug, &role, &email, &maxUses, &uses, &expiresAt, &revokedAt)
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
	if maxUses != nil && uses >= *maxUses {
		return zero, ErrInviteLinkExhausted
	}

	// Email-bound: only the matching VERIFIED address may redeem (defense in depth —
	// a forwarded link still only works for the intended recipient).
	if email != "" {
		u, err := s.getUserByID(ctx, redeemerUserID)
		if err != nil {
			return zero, err
		}
		if u == nil || u.Email == nil || !u.EmailVerified || NormalizeEmail(*u.Email) != email {
			return zero, ErrInviteEmailMismatch
		}
	}

	// Idempotency: already holds this role => success, no use consumed.
	already, err := subjectHasRole(ctx, q, groupID, redeemerUserID, role)
	if err != nil {
		return zero, err
	}
	if !already {
		if err := s.requireMFAForRoleAssignment(ctx, q, persona, redeemerUserID, SubjectKindUser, role); err != nil {
			return zero, err
		}
		if err := NewPermissionGroupStore(q).AssignRole(ctx, groupID, redeemerUserID, SubjectKindUser, role); err != nil {
			return zero, err
		}
		if _, err := q.Exec(ctx,
			`UPDATE profiles.group_invite_links SET uses = uses + 1, updated_at = now() WHERE id = $1::uuid`,
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
