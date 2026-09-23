package embedded

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
)

// GenerateAvailableUsername tries base, then minimal numeric suffixes, then a short fallback.
func (s *engine) GenerateAvailableUsername(ctx context.Context, base string) string {
	base = s.cfg.Username.Derive(base)
	if base == "" {
		base = "user"
	}
	// If available, return immediately.
	if s.usernameAvailable(ctx, base) {
		return base
	}
	// Try numbered suffixes
	for i := 1; i <= 999; i++ {
		candidate := s.cfg.Username.WithSuffix(base, fmt.Sprintf("%d", i))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	// Fallback: base + random 4 digits (global rand is auto-seeded since Go 1.20)
	for tries := 0; tries < 100; tries++ {
		candidate := s.cfg.Username.WithSuffix(base, fmt.Sprintf("%04d", rand.Intn(10000)))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	return s.cfg.Username.WithSuffix(base, "_user")
}

// usernameAvailable reports whether username is free. getUserByUsername returns
// pgx.ErrNoRows for a free name, so ErrNoRows is the available case (#111: the
// organization-slug reservation plane was removed, so username uniqueness is the only
// constraint).
func (s *engine) usernameAvailable(ctx context.Context, username string) bool {
	if s.pg == nil {
		return true
	}
	var taken bool
	err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM name_claims WHERE owner_kind='user' AND persona='' AND name=lower($1) AND (canonical OR expires_at IS NULL OR expires_at>$2))`, username, s.namingNow()).Scan(&taken)
	return err == nil && !taken
}

// DeriveUsernameForOAuth prefers provider-preferred usernames; falls back to email local part or display name.
func (s *engine) DeriveUsernameForOAuth(ctx context.Context, provider, preferred, email, displayName string) string {
	// Highest: preferred username from provider
	if strings.TrimSpace(preferred) != "" {
		return s.GenerateAvailableUsername(ctx, preferred)
	}
	// Next: email local part
	if strings.TrimSpace(email) != "" {
		local := email
		if i := strings.IndexByte(local, '@'); i > 0 {
			local = local[:i]
		}
		if strings.TrimSpace(local) != "" {
			return s.GenerateAvailableUsername(ctx, local)
		}
	}
	// Next: display name
	if strings.TrimSpace(displayName) != "" {
		return s.GenerateAvailableUsername(ctx, displayName)
	}
	// Last: provider-based generic
	base := provider
	if strings.TrimSpace(base) == "" {
		base = "user"
	}
	return s.GenerateAvailableUsername(ctx, base+"_user")
}
