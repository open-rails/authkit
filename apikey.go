// Package authkit holds authentication primitives shared between authkit's
// issuing core and its verification layer: plain data types, opaque-credential
// parsing, and sentinel errors that carry NO dependency on Postgres or the rest
// of core (stdlib only). It exists so the verification path — and, later, a
// standalone verify module (agents #110/#107) — can depend on these without
// pulling in the storage layer. The core package re-exports every symbol here as
// an alias, so existing callers using core.X are unaffected.
package authkit

import (
	"errors"
	"strings"
)

var (
	// ErrInvalidAccessToken indicates an API key that does not exist, has a bad
	// secret, or whose owning permission group is gone. Deliberately indistinguishable from
	// a malformed token so callers learn nothing from the error.
	ErrInvalidAccessToken = errors.New("invalid_token")
	// ErrAccessTokenRevoked indicates the API key was explicitly revoked.
	ErrAccessTokenRevoked = errors.New("token_revoked")
	// ErrAccessTokenExpired indicates the API key is past its expires_at.
	ErrAccessTokenExpired = errors.New("token_expired")
)

// apiKeyTypeSegment is the FIXED, non-configurable type tag. The full marker is
// "<app>_st_" when an app prefix is set, or bare "st_" when it is empty.
const apiKeyTypeSegment = "st_"

// APIKeyMarker returns the leading marker that identifies an API key for the given
// application prefix: "<prefix>_st_" when prefix is non-empty, else "st_".
func APIKeyMarker(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return apiKeyTypeSegment
	}
	return prefix + "_" + apiKeyTypeSegment
}

// HasAPIKeyPrefix reports whether token carries the API-key marker for prefix.
// Used by middleware to route to the API-key path before attempting JWT verification.
func HasAPIKeyPrefix(prefix, token string) bool {
	return strings.HasPrefix(token, APIKeyMarker(prefix))
}

// FormatAPIKey assembles the full presented token: <marker><key_id>_<secret>.
func FormatAPIKey(prefix, keyID, secret string) string {
	return APIKeyMarker(prefix) + keyID + "_" + secret
}

// ParseAPIKey splits a presented token into its key_id and secret. key_id and
// secret are base62 (no underscores), so the first "_" after the marker is the
// unambiguous delimiter. ok is false if the token lacks the marker or either
// part is empty.
func ParseAPIKey(prefix, token string) (keyID, secret string, ok bool) {
	marker := APIKeyMarker(prefix)
	if !strings.HasPrefix(token, marker) {
		return "", "", false
	}
	rest := token[len(marker):]
	keyID, secret, found := strings.Cut(rest, "_")
	if !found || keyID == "" || secret == "" {
		return "", "", false
	}
	return keyID, secret, true
}

// ResolvedAPIKey is the API-key resolution result. Permissions is the key's role
// resolved to its effective permission set AT VERIFY TIME (so a role edit is
// reflected immediately — perms are never frozen into the key).
type ResolvedAPIKey struct {
	APIKeyID string
	KeyID    string
	// PermissionGroupID is the controlling permission-group id.
	PermissionGroupID string
	// Persona / InstanceSlug identify the owning permission-group INSTANCE the
	// key was minted on (#248). InstanceSlug is "" for singleton personas (root).
	// The verify layer binds the key's token-carried permissions to this exact
	// instance; descendant/walk-down authority is deliberately deferred.
	Persona      string
	InstanceSlug string
	Role         string
	Permissions  []string
}
