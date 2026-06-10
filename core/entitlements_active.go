package core

import (
	"strings"
	"time"

	entpg "github.com/open-rails/authkit/entitlements"
)

// entitlementActive reports whether an entitlement is in force at time `now`.
//
// AuthKit treats RevokedAt/ExpiresAt as authoritative lifecycle signals: an
// entitlement is inactive once it has been revoked (RevokedAt set and not in the
// future) or once it has expired (ExpiresAt set and not in the future). This is
// defense-in-depth — providers are still expected to filter at the source, but
// AuthKit must never surface a grant the provider explicitly marked dead.
func entitlementActive(e entpg.Entitlement, now time.Time) bool {
	if e.RevokedAt != nil && !now.Before(*e.RevokedAt) {
		return false
	}
	if e.ExpiresAt != nil && !now.Before(*e.ExpiresAt) {
		return false
	}
	return true
}

// activeEntitlements returns only the entitlements that are in force at `now`,
// preserving order and metadata.
func activeEntitlements(details []entpg.Entitlement, now time.Time) []entpg.Entitlement {
	out := make([]entpg.Entitlement, 0, len(details))
	for _, e := range details {
		if entitlementActive(e, now) {
			out = append(out, e)
		}
	}
	return out
}

// activeEntitlementNames flattens entitlements to their names, dropping revoked,
// expired, empty, and duplicate (case-insensitive) entries. The result is always
// non-nil so the `entitlements` claim serializes as `[]` rather than `null`.
func activeEntitlementNames(details []entpg.Entitlement, now time.Time) []string {
	out := make([]string, 0, len(details))
	seen := make(map[string]struct{}, len(details))
	for _, e := range details {
		if !entitlementActive(e, now) {
			continue
		}
		name := strings.TrimSpace(e.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	return out
}
