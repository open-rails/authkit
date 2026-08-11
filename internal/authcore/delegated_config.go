package authcore

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Delegated mint defaults (#261). Applied to unset DelegatedConfig fields
// before the floor <= default <= ceiling boot check.
const (
	DefaultDelegatedTTLFloor   = time.Minute
	DefaultDelegatedTTLDefault = 15 * time.Minute
	DefaultDelegatedTTLCeiling = time.Hour
)

// DelegatedAttributeProvider is the HOST-INJECTED seam of the delegated-token
// mint route (#261): given the authenticated user, it returns the attributes
// and per-user document references to stamp into the minted token. AuthKit
// never learns what the attributes mean (billing tiers, entitlements, …) —
// same dependency idiom as WithEntitlements. A nil attributes/documents map is
// fine; an error refuses the mint.
type DelegatedAttributeProvider func(ctx context.Context, userID string) (attributes map[string]any, documents map[string]string, err error)

// normalizeDelegatedConfig applies defaults and refuses an impossible TTL
// triple at construction (#231 house style: boot refusal, never a silent
// config clamp). Zero-value config (route disabled) passes through, but TTLs
// set while the route is disabled are dead config and refuse too.
func normalizeDelegatedConfig(cfg DelegatedConfig) (DelegatedConfig, error) {
	cfg.Audiences = normalizeDedupStrings(cfg.Audiences)
	if len(cfg.Audiences) == 0 {
		if cfg.TTLFloor != 0 || cfg.TTLDefault != 0 || cfg.TTLCeiling != 0 {
			return DelegatedConfig{}, fmt.Errorf("authkit: Delegated TTLs are set but Delegated.Audiences is empty — the mint route is disabled without an audience allowlist, so these TTLs can never apply")
		}
		return cfg, nil
	}
	if cfg.TTLFloor < 0 || cfg.TTLDefault < 0 || cfg.TTLCeiling < 0 {
		return DelegatedConfig{}, fmt.Errorf("authkit: Delegated TTLs must not be negative (floor=%v default=%v ceiling=%v)", cfg.TTLFloor, cfg.TTLDefault, cfg.TTLCeiling)
	}
	if cfg.TTLFloor == 0 {
		cfg.TTLFloor = DefaultDelegatedTTLFloor
	}
	if cfg.TTLDefault == 0 {
		cfg.TTLDefault = DefaultDelegatedTTLDefault
	}
	if cfg.TTLCeiling == 0 {
		cfg.TTLCeiling = DefaultDelegatedTTLCeiling
	}
	if cfg.TTLFloor > cfg.TTLCeiling || cfg.TTLDefault < cfg.TTLFloor || cfg.TTLDefault > cfg.TTLCeiling {
		return DelegatedConfig{}, fmt.Errorf("authkit: Delegated TTLs must satisfy floor <= default <= ceiling (floor=%v default=%v ceiling=%v)", cfg.TTLFloor, cfg.TTLDefault, cfg.TTLCeiling)
	}
	return cfg, nil
}

// normalizeDedupStrings trims, drops empties, and dedups preserving order.
func normalizeDedupStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
