package core

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"

	"github.com/jackc/pgx/v5"
)

// GenerateAvailableUsername tries base, then minimal numeric suffixes, then a short fallback.
// Deprecated: use s.Users().GenerateAvailableUsername.
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
		candidate := usernameWithSuffix(base, fmt.Sprintf("%d", i))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	// Fallback: base + random 4 digits (global rand is auto-seeded since Go 1.20)
	for tries := 0; tries < 100; tries++ {
		candidate := usernameWithSuffix(base, fmt.Sprintf("%04d", rand.Intn(10000)))
		if s.usernameAvailable(ctx, candidate) {
			return candidate
		}
	}
	return usernameWithSuffix(base, "_user")
}

// usernameWithSuffix appends suffix, trimming base so the result stays within
// usernameMaxLen and remains valid for createUser.
func usernameWithSuffix(base, suffix string) string {
	if max := usernameMaxLen - len(suffix); len(base) > max {
		base = base[:max]
	}
	return base + suffix
}

// usernameAvailable reports whether username is free. getUserByUsername returns
// pgx.ErrNoRows for a free name, so ErrNoRows is the available case (#111: the
// org-slug reservation plane was removed, so username uniqueness is the only
// constraint).
func (s *Service) usernameAvailable(ctx context.Context, username string) bool {
	if s.pg == nil {
		return true
	}
	u, err := s.getUserByUsername(ctx, username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	return u == nil
}

// DeriveUsernameForOAuth prefers provider-preferred usernames; falls back to email local part or display name.
// Deprecated: use s.Users().DeriveUsernameForOAuth.
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

// cleanUsername normalizes to lowercase, keeps [a-z0-9_], ensures a letter
// prefix, and keeps length within [usernameMinLen, usernameMaxLen] so derived
// usernames always satisfy ValidateUsername.
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
	if len(out) > usernameMaxLen {
		out = out[:usernameMaxLen]
	}
	if len(out) < usernameMinLen {
		out += "_user"
	}
	return out
}
