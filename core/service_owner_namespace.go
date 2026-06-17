package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

var (
	ErrOwnerSlugTaken    = errors.New("owner_slug_taken")
	ErrPersonalOrgLocked = errors.New("personal_org_locked")
	ErrInviteNotFound    = errors.New("org_invite_not_found")
	ErrInviteNotPending  = errors.New("org_invite_not_pending")
	ErrInviteNotForUser  = errors.New("org_invite_not_for_user")
	ErrInviteExpired     = errors.New("org_invite_expired")
	// ErrInviteRoleExceedsGrantor is returned when an invite's role confers
	// permissions the inviter does not (currently) hold — the no-escalation
	// invariant. Enforced at invite-create time and re-checked at accept time
	// (the inviter may have been demoted in between).
	ErrInviteRoleExceedsGrantor = errors.New("org_invite_role_exceeds_grantor")
	ErrPersonalOrgNotFound      = errors.New("personal_org_not_found")
)

func ownerSlugFromUsername(username string) string {
	s := strings.ToLower(strings.TrimSpace(username))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteByte(ch)
			prevDash = false
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
			prevDash = false
		case ch == '-' || ch == '_':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}

func (s *Service) ownerSlugAvailable(ctx context.Context, slug, excludeUserID, excludeOrgID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateOrgSlug(slug); err != nil {
		return false, err
	}
	reuseCutoff := time.Now().UTC().Add(-renameReuseHold)
	exists, err := s.q.OwnerReservedNameExists(ctx, slug)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	exists, err = s.q.OwnerSlugUserExists(ctx, db.OwnerSlugUserExistsParams{Slug: slug, ExcludeUserID: strings.TrimSpace(excludeUserID)})
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	// Squat protection from recent rename history. A historical `from_slug`
	// blocks reuse by anyone except the row that owned it until
	// renameReuseHold expires. Same-row reclaim is allowed via the exclude
	// parameters. Joins to owner rows without filtering soft deletes: soft
	// deletion keeps the namespace held, while hard deletion removes/cascades
	// the owner row and allows eventual reuse.
	exists, err = s.q.OwnerSlugUserRenameHeld(ctx, db.OwnerSlugUserRenameHeldParams{Slug: slug, ReuseCutoff: reuseCutoff, ExcludeUserID: strings.TrimSpace(excludeUserID)})
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	exists, err = s.q.OwnerSlugOrgExists(ctx, db.OwnerSlugOrgExistsParams{Slug: slug, ExcludeOrgID: strings.TrimSpace(excludeOrgID)})
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	exists, err = s.q.OwnerSlugOrgRenameHeld(ctx, db.OwnerSlugOrgRenameHeldParams{Slug: slug, ReuseCutoff: reuseCutoff, ExcludeOrgID: strings.TrimSpace(excludeOrgID)})
	if err != nil {
		return false, err
	}
	return !exists, nil
}

func (s *Service) ensureOwnerSlugAvailable(ctx context.Context, slug, excludeUserID, excludeOrgID string) error {
	ok, err := s.ownerSlugAvailable(ctx, slug, excludeUserID, excludeOrgID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOwnerSlugTaken
	}
	return nil
}

func (s *Service) ensureUserOwnerSlugAvailable(ctx context.Context, userID, username string) (string, error) {
	slug, excludeOrgID, err := s.userOwnerSlugAvailability(ctx, userID, username)
	if err != nil {
		return "", err
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, userID, excludeOrgID); err != nil {
		return "", err
	}
	return slug, nil
}

func (s *Service) userOwnerSlugAvailability(ctx context.Context, userID, username string) (slug, excludeOrgID string, err error) {
	userID = strings.TrimSpace(userID)
	slug = ownerSlugFromUsername(username)
	if userID == "" || slug == "" {
		return "", "", fmt.Errorf("invalid_user_owner_namespace")
	}
	if err := validateOrgSlug(slug); err != nil {
		return "", "", err
	}

	// A user's personal org is the org-shaped half of the same owner identity.
	// It must not make an otherwise idempotent user update look like a namespace
	// collision with a different owner.
	personalOrg, err := s.q.PersonalOrgIDSlugByOwner(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return slug, "", nil
	}
	if err != nil {
		return "", "", err
	}
	if strings.EqualFold(strings.TrimSpace(personalOrg.Slug), slug) {
		return slug, strings.TrimSpace(personalOrg.ID), nil
	}
	return slug, "", nil
}

func (s *Service) GetPersonalOrgForUser(ctx context.Context, userID string) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	row, err := s.q.PersonalOrgByOwner(ctx, userID)
	if err != nil {
		return nil, ErrPersonalOrgNotFound
	}
	return &Org{ID: row.ID, Slug: row.Slug, IsPersonal: row.IsPersonal, OwnerUserID: row.OwnerUserID}, nil
}

// ListUserSlugAliases returns every historical username this user has
// held (excluding the current one). Source: `user_renames.from_slug`
// (issue #58). Distinct values; order by usage timeline.
func (s *Service) ListUserSlugAliases(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	out, err := s.q.UserSlugAliases(ctx, userID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = make([]string, 0, 4)
	}
	return out, nil
}

func (s *Service) ResolveUserBySlug(ctx context.Context, slug string) (userID string, username string, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", err
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return "", "", fmt.Errorf("invalid_slug")
	}
	slug = strings.ToLower(slug)
	if row, err := s.q.UserBySlug(ctx, &slug); err == nil {
		return row.ID, row.Username, nil
	}
	// Fallback to renames table (issue #58). Most-recent rename wins
	// when a slug has been used by multiple users at different times
	// (only possible after hard-delete + reuse).
	row, err := s.q.UserBySlugViaRename(ctx, slug)
	if err != nil {
		return "", "", ErrUserNotFound
	}
	return row.ID, row.Username, nil
}

// ListOrgAliases returns every historical slug this org has held
// (excluding the current one). Source: `org_renames.from_slug` (issue
// #58). Distinct values.
func (s *Service) ListOrgAliases(ctx context.Context, orgID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("invalid_org")
	}
	out, err := s.q.OrgAliases(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = make([]string, 0, 4)
	}
	return out, nil
}

func (s *Service) ensurePersonalOrgForUser(ctx context.Context, userID, username string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	// (issue 60) Gated by AutoCreatePersonalOrgsEnabled at every call site; no
	// org-mode check here.
	userID = strings.TrimSpace(userID)
	slug := ownerSlugFromUsername(username)
	if userID == "" || slug == "" {
		return fmt.Errorf("invalid_personal_org")
	}
	if _, err := s.ensureUserOwnerSlugAvailable(ctx, userID, username); err != nil {
		return err
	}

	orgIDToInsert, err := newUUIDV7String()
	if err != nil {
		return err
	}
	orgID, err := s.q.PersonalOrgUpsert(ctx, db.PersonalOrgUpsertParams{ID: orgIDToInsert, Slug: slug, OwnerUserID: userID})
	if err != nil {
		return err
	}

	if err := s.q.OrgRolesSeedOwnerMember(ctx, db.OrgRolesSeedOwnerMemberParams{OrgID: orgID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
		return err
	}
	if err := s.q.OrgMembershipUpsertRole(ctx, db.OrgMembershipUpsertRoleParams{OrgID: orgID, UserID: userID, Role: orgOwnerRole}); err != nil {
		return err
	}
	// Seed owner=`*` + any app-declared default roles for the personal org.
	if err := s.seedRolePermissionDefaults(ctx, orgID); err != nil {
		return err
	}
	return nil
}
