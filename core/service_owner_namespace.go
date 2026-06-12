package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

var (
	ErrOwnerSlugTaken         = errors.New("owner_slug_taken")
	ErrPersonalTenantLocked   = errors.New("personal_tenant_locked")
	ErrInviteNotFound         = errors.New("tenant_invite_not_found")
	ErrInviteNotPending       = errors.New("tenant_invite_not_pending")
	ErrInviteNotForUser       = errors.New("tenant_invite_not_for_user")
	ErrInviteExpired          = errors.New("tenant_invite_expired")
	ErrPersonalTenantNotFound = errors.New("personal_tenant_not_found")
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

func (s *Service) ownerSlugAvailable(ctx context.Context, slug, excludeUserID, excludeTenantID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateTenantSlug(slug); err != nil {
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
	exists, err = s.q.OwnerSlugTenantExists(ctx, db.OwnerSlugTenantExistsParams{Slug: slug, ExcludeTenantID: strings.TrimSpace(excludeTenantID)})
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	exists, err = s.q.OwnerSlugTenantRenameHeld(ctx, db.OwnerSlugTenantRenameHeldParams{Slug: slug, ReuseCutoff: reuseCutoff, ExcludeTenantID: strings.TrimSpace(excludeTenantID)})
	if err != nil {
		return false, err
	}
	return !exists, nil
}

func (s *Service) ensureOwnerSlugAvailable(ctx context.Context, slug, excludeUserID, excludeTenantID string) error {
	ok, err := s.ownerSlugAvailable(ctx, slug, excludeUserID, excludeTenantID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOwnerSlugTaken
	}
	return nil
}

func (s *Service) GetPersonalTenantForUser(ctx context.Context, userID string) (*Tenant, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	row, err := s.q.PersonalTenantByOwner(ctx, userID)
	if err != nil {
		return nil, ErrPersonalTenantNotFound
	}
	return &Tenant{ID: row.ID, Slug: row.Slug, IsPersonal: row.IsPersonal, OwnerUserID: row.OwnerUserID}, nil
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

// ListTenantAliases returns every historical slug this tenant has held
// (excluding the current one). Source: `tenant_renames.from_slug` (issue
// #58). Distinct values.
func (s *Service) ListTenantAliases(ctx context.Context, tenantID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("invalid_tenant")
	}
	out, err := s.q.TenantAliases(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = make([]string, 0, 4)
	}
	return out, nil
}

func (s *Service) ensurePersonalTenantForUser(ctx context.Context, userID, username string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	// (issue 60) Gated by AutoCreatePersonalTenantsEnabled at every call site; no
	// tenant-mode check here.
	userID = strings.TrimSpace(userID)
	slug := ownerSlugFromUsername(username)
	if userID == "" || slug == "" {
		return fmt.Errorf("invalid_personal_tenant")
	}
	if err := validateTenantSlug(slug); err != nil {
		return err
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, userID, ""); err != nil {
		return err
	}

	tenantIDToInsert, err := newUUIDV7String()
	if err != nil {
		return err
	}
	tenantID, err := s.q.PersonalTenantUpsert(ctx, db.PersonalTenantUpsertParams{ID: tenantIDToInsert, Slug: slug, OwnerUserID: userID})
	if err != nil {
		return err
	}

	if err := s.q.TenantRolesSeedOwnerMember(ctx, db.TenantRolesSeedOwnerMemberParams{TenantID: tenantID, OwnerRole: tenantOwnerRole, MemberRole: tenantMemberRole}); err != nil {
		return err
	}
	if err := s.q.TenantMembershipUpsertRole(ctx, db.TenantMembershipUpsertRoleParams{TenantID: tenantID, UserID: userID, Role: tenantOwnerRole}); err != nil {
		return err
	}
	// Seed owner=`*` + any app-declared default roles for the personal tenant.
	if err := s.seedRolePermissionDefaults(ctx, tenantID); err != nil {
		return err
	}
	return nil
}
