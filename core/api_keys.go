package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/internal/db"
)

// API keys: long-lived, revocable shared-secret bearer credentials
// owned by an org (not a person), for machine/automation callers. An API key carries
// a set of app-defined PERMISSION strings (opaque to authkit; the embedding app
// defines and enforces what each one means). See agents #43 (lifecycle) and #44
// (permission model).

var (
	// ErrInvalidAccessToken indicates an API key that does not exist, has a bad
	// secret, or whose owning org is gone. Deliberately indistinguishable from
	// a malformed token so callers learn nothing from the error.
	ErrInvalidAccessToken = errors.New("invalid_token")
	// ErrAccessTokenRevoked indicates the API key was explicitly revoked.
	ErrAccessTokenRevoked = errors.New("token_revoked")
	// ErrAccessTokenExpired indicates the API key is past its expires_at.
	ErrAccessTokenExpired = errors.New("token_expired")
)

const (
	// apiKeyTypeSegment is the FIXED, non-configurable type tag. The full marker is
	// "<app>_st_" when an app prefix is set, or bare "st_" when it is empty.
	apiKeyTypeSegment    = "st_"
	apiKeyKeyIDLen       = 16  // base62 chars; non-secret public lookup id
	apiKeySecretLen      = 43  // base62 chars ~= 256 bits of entropy
	apiKeyResourceMaxLen = 128 // DB check constraint; resource strings are host-defined.
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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

func randBase62(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(base62Alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = base62Alphabet[idx.Int64()]
	}
	return string(out), nil
}

func sha256Raw(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// APIKey is the non-secret metadata view of an API key. The secret is never
// stored or returned after creation.
type APIKey struct {
	ID          string
	KeyID       string
	Name        string
	Permissions []string
	Resources   []APIKeyResource
	CreatedBy   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// APIKeyResource is one opaque, host-defined resource scope carried by
// an API key. AuthKit stores and returns the exact Kind/ID pair but does not
// interpret it. Hosts own resource semantics, including any wildcard-looking IDs
// such as "*".
type APIKeyResource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// ResolvedAPIKey is the resource-aware API-key resolution result.
type ResolvedAPIKey struct {
	APIKeyID string
	KeyID    string
	// OrgID is the immutable org uuid — the canonical identifier for
	// persistence and cross-service references. OrgSlug is the mutable
	// human-readable name, for presentation/logging only.
	OrgID       string
	OrgSlug     string
	Permissions []string
	Resources   []APIKeyResource
}

// APIKeyMintOptions is the resource-aware API-key mint request. The token
// format remains unchanged; resources are stored beside the opaque credential.
type APIKeyMintOptions struct {
	Name        string
	Permissions []string
	Resources   []APIKeyResource
	CreatedBy   string
	ExpiresAt   *time.Time
}

// ResourceScopeAuthorizationRequest is passed to a host callback when the HTTP
// API-key mint route receives resource scopes. AuthKit has already validated shape
// and permission no-escalation before this hook runs.
type ResourceScopeAuthorizationRequest struct {
	OrgSlug     string
	ActorUserID string
	Permissions []string
	Resources   []APIKeyResource
}

// ResourceScopeAuthorizer is an optional host callback for API-key resource-scope
// no-escalation. Return an error to deny minting. AuthKit treats resource kinds
// and IDs as opaque and never interprets their semantics itself.
type ResourceScopeAuthorizer func(ctx context.Context, req ResourceScopeAuthorizationRequest) error

func (s *Service) AuthorizeAPIKeyResources(ctx context.Context, req ResourceScopeAuthorizationRequest) error {
	resources, err := normalizeAPIKeyResources(req.Resources)
	if err != nil {
		return err
	}
	if s.opts.ResourceScopeAuthorizer == nil {
		return nil
	}
	req.OrgSlug = strings.TrimSpace(req.OrgSlug)
	req.ActorUserID = strings.TrimSpace(req.ActorUserID)
	req.Resources = resources
	req.Permissions = dedupeStrings(req.Permissions)
	return s.opts.ResourceScopeAuthorizer(ctx, req)
}

func normalizeAPIKeyResources(in []APIKeyResource) ([]APIKeyResource, error) {
	if in == nil {
		return []APIKeyResource{}, nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]APIKeyResource, 0, len(in))
	for _, r := range in {
		kind := strings.TrimSpace(r.Kind)
		id := strings.TrimSpace(r.ID)
		if kind == "" || id == "" || len(kind) > apiKeyResourceMaxLen || len(id) > apiKeyResourceMaxLen {
			return nil, errors.New("invalid_resource")
		}
		key := kind + "\x00" + id
		if seen[key] {
			return nil, errors.New("duplicate_resource")
		}
		seen[key] = true
		out = append(out, APIKeyResource{Kind: kind, ID: id})
	}
	return out, nil
}

// MintAPIKey inserts a new API key for the org and returns its metadata plus
// the full plaintext token (shown ONCE). permissions must already be authorized
// by the caller (the grant decision lives in the HTTP handler / host hook).
// expiresAt is optional (nil = no expiry) and is capped to APIKeyMaxTTL
// when set.
func (s *Service) MintAPIKey(ctx context.Context, orgSlug, name string, permissions []string, createdBy string, expiresAt *time.Time) (APIKey, string, error) {
	return s.MintAPIKeyWithOptions(ctx, orgSlug, APIKeyMintOptions{
		Name:        name,
		Permissions: permissions,
		CreatedBy:   createdBy,
		ExpiresAt:   expiresAt,
	})
}

// MintAPIKeyWithOptions inserts a new API key using the resource-aware mint
// contract. Permissions and resources must already be authorized by the caller.
func (s *Service) MintAPIKeyWithOptions(ctx context.Context, orgSlug string, opts APIKeyMintOptions) (APIKey, string, error) {
	if err := s.requirePG(); err != nil {
		return APIKey{}, "", err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return APIKey{}, "", err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return APIKey{}, "", errors.New("missing_name")
	}
	permissions := opts.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	resources, err := normalizeAPIKeyResources(opts.Resources)
	if err != nil {
		return APIKey{}, "", err
	}

	now := time.Now().UTC()
	expiresAt := opts.ExpiresAt
	if expiresAt != nil && !expiresAt.After(now) {
		return APIKey{}, "", errors.New("invalid_expiry")
	}
	if maxTTL := s.opts.APIKeyMaxTTL; maxTTL > 0 {
		capAt := now.Add(maxTTL)
		if expiresAt == nil || expiresAt.After(capAt) {
			expiresAt = &capAt
		}
	}

	secret, err := randBase62(apiKeySecretLen)
	if err != nil {
		return APIKey{}, "", err
	}
	secretHash := sha256Raw(secret)

	var createdByArg *string
	if v := strings.TrimSpace(opts.CreatedBy); v != "" {
		createdByArg = &v
	}

	// key_id is unique; retry a few times on the (astronomically unlikely)
	// collision rather than failing the request.
	var out APIKey
	for attempt := 0; attempt < 5; attempt++ {
		keyID, err := randBase62(apiKeyKeyIDLen)
		if err != nil {
			return APIKey{}, "", err
		}
		tx, err := s.pg.Begin(ctx)
		if err != nil {
			return APIKey{}, "", err
		}
		qtx := s.qtx(tx)
		ins, err := qtx.APIKeyInsert(ctx, db.APIKeyInsertParams{
			OrgID:      org.ID,
			KeyID:      keyID,
			SecretHash: secretHash,
			Name:       name,
			CreatedBy:  createdByArg,
			ExpiresAt:  expiresAt,
		})
		if err != nil {
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, "key_id") {
				continue // key_id collision; regenerate
			}
			return APIKey{}, "", err
		}
		id := ins.ID
		for _, permission := range dedupeStrings(permissions) {
			if err := qtx.APIKeyPermissionInsert(ctx, db.APIKeyPermissionInsertParams{ApiKeyID: id, Permission: permission}); err != nil {
				_ = tx.Rollback(ctx)
				return APIKey{}, "", err
			}
		}
		for _, r := range resources {
			if err := qtx.APIKeyResourceInsert(ctx, db.APIKeyResourceInsertParams{ApiKeyID: id, Kind: r.Kind, ResourceID: r.ID}); err != nil {
				_ = tx.Rollback(ctx)
				return APIKey{}, "", err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return APIKey{}, "", err
		}
		out = APIKey{
			ID:          id,
			KeyID:       keyID,
			Name:        name,
			Permissions: permissions,
			Resources:   resources,
			CreatedBy:   strings.TrimSpace(opts.CreatedBy),
			CreatedAt:   ins.CreatedAt,
			ExpiresAt:   expiresAt,
		}
		return out, FormatAPIKey(s.opts.APIKeyPrefix, keyID, secret), nil
	}
	return APIKey{}, "", errors.New("key_id_generation_failed")
}

// ListAPIKeys returns metadata for every API key of the org (including
// revoked/expired ones, so an admin can see and clean them up). The secret is
// never returned.
func (s *Service) ListAPIKeys(ctx context.Context, orgSlug string) ([]APIKey, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.APIKeysByOrg(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	var out []APIKey
	for _, r := range rows {
		out = append(out, APIKey{
			ID:         r.ID,
			KeyID:      r.KeyID,
			Name:       r.Name,
			CreatedBy:  r.CreatedBy,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
			ExpiresAt:  r.ExpiresAt,
			RevokedAt:  r.RevokedAt,
		})
	}
	if err := s.loadAPIKeyPermissions(ctx, out); err != nil {
		return nil, err
	}
	if err := s.loadAPIKeyResources(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeAPIKey marks the API key revoked. It is scoped to the org so a
// token cannot be revoked from a different org. Returns false if no matching,
// not-already-revoked token exists.
func (s *Service) RevokeAPIKey(ctx context.Context, orgSlug, tokenID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	n, err := s.q.APIKeyRevoke(ctx, db.APIKeyRevokeParams{ID: strings.TrimSpace(tokenID), OrgID: org.ID})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ResolveAPIKey validates a presented API key (key_id + secret) and returns
// the owning org's current slug and the token's frozen permissions. It performs
// an indexed lookup by key_id, a constant-time secret compare, and revoked /
// expired / org-deleted checks, then best-effort async-touches last_used_at.
func (s *Service) ResolveAPIKey(ctx context.Context, keyID, secret string) (orgSlug string, permissions []string, err error) {
	resolved, err := s.ResolveAPIKeyWithResources(ctx, keyID, secret)
	if err != nil {
		return "", nil, err
	}
	return resolved.OrgSlug, resolved.Permissions, nil
}

// ResolveAPIKeyWithResources validates a presented API key and returns the
// full resource-aware result. Existing tokens with no resources return an empty
// Resources slice and remain org-wide for hosts that use the compatibility
// resolver.
func (s *Service) ResolveAPIKeyWithResources(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error) {
	if err := s.requirePG(); err != nil {
		return ResolvedAPIKey{}, err
	}
	row, err := s.q.APIKeyByKeyID(ctx, keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResolvedAPIKey{}, ErrInvalidAccessToken
		}
		return ResolvedAPIKey{}, err
	}

	// Constant-time secret comparison.
	if subtle.ConstantTimeCompare(row.SecretHash, sha256Raw(secret)) != 1 {
		return ResolvedAPIKey{}, ErrInvalidAccessToken
	}
	if row.RevokedAt != nil {
		return ResolvedAPIKey{}, ErrAccessTokenRevoked
	}
	if row.ExpiresAt != nil && !row.ExpiresAt.After(time.Now().UTC()) {
		return ResolvedAPIKey{}, ErrAccessTokenExpired
	}
	if row.OrgDeletedAt != nil {
		return ResolvedAPIKey{}, ErrInvalidAccessToken
	}

	s.touchAccessTokenAsync(row.ID)
	gotPerms, err := s.listAPIKeyPermissions(ctx, row.ID)
	if err != nil {
		return ResolvedAPIKey{}, err
	}
	resources, err := s.listAPIKeyResources(ctx, row.ID)
	if err != nil {
		return ResolvedAPIKey{}, err
	}
	return ResolvedAPIKey{
		APIKeyID:    row.ID,
		KeyID:       keyID,
		OrgID:       row.OrgID,
		OrgSlug:     row.Slug,
		Permissions: gotPerms,
		Resources:   resources,
	}, nil
}

// touchAccessTokenAsync updates last_used_at without blocking the request. A
// failure here is non-critical (auth already succeeded).
func (s *Service) touchAccessTokenAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.q.APIKeyTouchLastUsed(ctx, id)
	}()
}

func (s *Service) loadAPIKeyPermissions(ctx context.Context, tokens []APIKey) error {
	if len(tokens) == 0 {
		return nil
	}
	ids := make([]string, 0, len(tokens))
	byID := make(map[string]int, len(tokens))
	for i := range tokens {
		tokens[i].Permissions = []string{}
		ids = append(ids, tokens[i].ID)
		byID[tokens[i].ID] = i
	}
	rows, err := s.q.APIKeyPermissionsByAPIKeyIDs(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if i, ok := byID[r.ApiKeyID]; ok {
			tokens[i].Permissions = append(tokens[i].Permissions, r.Permission)
		}
	}
	return nil
}

func (s *Service) listAPIKeyPermissions(ctx context.Context, tokenID string) ([]string, error) {
	perms, err := s.q.APIKeyPermissionsByAPIKeyID(ctx, strings.TrimSpace(tokenID))
	if err != nil {
		return nil, err
	}
	if perms == nil {
		perms = []string{}
	}
	return perms, nil
}

func (s *Service) loadAPIKeyResources(ctx context.Context, tokens []APIKey) error {
	if len(tokens) == 0 {
		return nil
	}
	ids := make([]string, 0, len(tokens))
	byID := make(map[string]int, len(tokens))
	for i := range tokens {
		tokens[i].Resources = []APIKeyResource{}
		ids = append(ids, tokens[i].ID)
		byID[tokens[i].ID] = i
	}
	rows, err := s.q.APIKeyResourcesByAPIKeyIDs(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if i, ok := byID[r.ApiKeyID]; ok {
			tokens[i].Resources = append(tokens[i].Resources, APIKeyResource{Kind: r.Kind, ID: r.ResourceID})
		}
	}
	return nil
}

func (s *Service) listAPIKeyResources(ctx context.Context, tokenID string) ([]APIKeyResource, error) {
	rows, err := s.q.APIKeyResourcesByAPIKeyID(ctx, strings.TrimSpace(tokenID))
	if err != nil {
		return nil, err
	}
	out := make([]APIKeyResource, 0, len(rows))
	for _, r := range rows {
		out = append(out, APIKeyResource{Kind: r.Kind, ID: r.ResourceID})
	}
	return out, nil
}
