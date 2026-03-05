package core

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// GenerateAvailableUsername tries base, then minimal numeric suffixes, then a short fallback.
func (s *Service) GenerateAvailableUsername(ctx context.Context, base string) string {
	base = cleanUsername(base)
	if base == "" {
		base = "user"
	}
	// If available, return immediately.
	if s.usernameAvailable(ctx, base) {
		return base
	}
	// Try numbered suffixes
	for i := 1; i <= 999; i++ {
		candidate := fmt.Sprintf("%s%d", base, i)
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	// Fallback: base + random 4 digits
	rand.Seed(time.Now().UnixNano())
	for tries := 0; tries < 100; tries++ {
		candidate := fmt.Sprintf("%s%04d", base, rand.Intn(10000))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	return base + "_user"
}

func (s *Service) usernameAvailable(ctx context.Context, username string) bool {
	if IsReservedUsername(username) {
		return false
	}
	u, err := s.getUserByUsername(ctx, username)
	return err == nil && u == nil
}

// DeriveUsernameForOAuth prefers provider-preferred usernames; falls back to email local part or display name.
func (s *Service) DeriveUsernameForOAuth(ctx context.Context, provider, preferred, email, displayName string) string {
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

// cleanUsername normalizes to lowercase, keeps [a-z0-9_], ensures a letter prefix, and caps length to 32.
func cleanUsername(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "user"
	}
	if out[0] < 'a' || out[0] > 'z' {
		out = "u" + out
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}
