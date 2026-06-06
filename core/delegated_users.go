package core

import (
	"context"
	"errors"
	"strings"
	"time"
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

	var out DelegatedUser
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.delegated_users (tenant_id, issuer, subject)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (tenant_id, issuer, subject) DO UPDATE
		  SET last_seen_at = now()
		RETURNING id::text, $4::text, issuer, subject, created_at, last_seen_at
	`, tenant.ID, issuer, subject, tenant.Slug).Scan(
		&out.ID, &out.TenantSlug, &out.Issuer, &out.Subject, &out.CreatedAt, &out.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
