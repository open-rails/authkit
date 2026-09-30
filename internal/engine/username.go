package engine

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	"github.com/open-rails/authkit/internal/naming"
)

// generateAvailableUsername tries base, then minimal numeric suffixes, then a short fallback.
func (s *Engine) generateAvailableUsername(ctx context.Context, base string) string {
	base = naming.Derive(s.cfg.Username, base)
	if base == "" {
		base = "user"
	}
	// If available, return immediately.
	if s.usernameAvailable(ctx, base) {
		return base
	}
	// Try numbered suffixes
	for i := 1; i <= 999; i++ {
		candidate := naming.WithSuffix(s.cfg.Username, base, fmt.Sprintf("%d", i))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	// Fallback: base + random 4 digits (global rand is auto-seeded since Go 1.20)
	for tries := 0; tries < 100; tries++ {
		candidate := naming.WithSuffix(s.cfg.Username, base, fmt.Sprintf("%04d", rand.Intn(10000)))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	return naming.WithSuffix(s.cfg.Username, base, "_user")
}

// usernameAvailable reports whether username is free; a failed read is not.
func (s *Engine) usernameAvailable(ctx context.Context, username string) bool {
	if s.pg == nil {
		return true
	}
	taken, err := s.usernameTaken(ctx, username)
	return err == nil && !taken
}

// deriveUsernameForOAuth prefers provider-preferred usernames; falls back to email local part or display name.
func (s *Engine) deriveUsernameForOAuth(ctx context.Context, provider, preferred, email, displayName string) string {
	// Highest: preferred username from provider
	if strings.TrimSpace(preferred) != "" {
		return s.generateAvailableUsername(ctx, preferred)
	}
	// Next: email local part
	if strings.TrimSpace(email) != "" {
		local := email
		if i := strings.IndexByte(local, '@'); i > 0 {
			local = local[:i]
		}
		if strings.TrimSpace(local) != "" {
			return s.generateAvailableUsername(ctx, local)
		}
	}
	// Next: display name
	if strings.TrimSpace(displayName) != "" {
		return s.generateAvailableUsername(ctx, displayName)
	}
	// Last: provider-based generic
	base := provider
	if strings.TrimSpace(base) == "" {
		base = "user"
	}
	return s.generateAvailableUsername(ctx, base+"_user")
}
