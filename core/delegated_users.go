package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

var ErrInvalidDelegatedUser = errors.New("invalid_delegated_user")

// DelegatedUser is the minimal local record for an external OIDC subject that
// was accepted under a tenant issuer. AuthKit deliberately stores only the
// stable OIDC identity tuple plus first/last-seen timestamps.
type DelegatedUser struct {
	ID         string
	TenantSlug string
	Issuer     string
	Subject    string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// TouchDelegatedUser records that tenantSlug accepted issuer+subject. The row
// is idempotent and updates last_seen_at on repeat use.
func (s *Service) TouchDelegatedUser(ctx context.Context, tenantSlug, issuer, subject string) (*DelegatedUser, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenantSlug = strings.ToLower(strings.TrimSpace(tenantSlug))
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	if tenantSlug == "" || issuer == "" || subject == "" {
		return nil, ErrInvalidDelegatedUser
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			return nil, ErrInvalidDelegatedUser
		}
		return nil, err
	}

	row, err := s.q.DelegatedUserTouch(ctx, db.DelegatedUserTouchParams{TenantID: tenant.ID, Issuer: issuer, Subject: subject})
	if err != nil {
		return nil, err
	}
	return &DelegatedUser{ID: row.ID, TenantSlug: tenant.Slug, Issuer: row.Issuer, Subject: row.Subject, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt}, nil
}
