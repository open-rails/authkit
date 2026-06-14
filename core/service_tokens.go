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

// Service Tokens (service tokens): long-lived, revocable bearer credentials
// owned by an org (not a person), for machine/automation callers. A service token carries
// a set of app-defined PERMISSION strings (opaque to authkit; the embedding app
// defines and enforces what each one means). See agents #43 (lifecycle) and #44
// (permission model).

var (
	// ErrInvalidAccessToken indicates a service token that does not exist, has a bad
	// secret, or whose owning org is gone. Deliberately indistinguishable from
	// a malformed token so callers learn nothing from the error.
	ErrInvalidAccessToken = errors.New("invalid_token")
	// ErrAccessTokenRevoked indicates the service token was explicitly revoked.
	ErrAccessTokenRevoked = errors.New("token_revoked")
	// ErrAccessTokenExpired indicates the service token is past its expires_at.
	ErrAccessTokenExpired = errors.New("token_expired")
)

const (
	// serviceTokenTypeSegment is the FIXED, non-configurable type tag. The full marker is
	// "<app>_st_" when an app prefix is set, or bare "st_" when it is empty.
	serviceTokenTypeSegment    = "st_"
	serviceTokenKeyIDLen       = 16  // base62 chars; non-secret public lookup id
	serviceTokenSecretLen      = 43  // base62 chars ~= 256 bits of entropy
	serviceTokenResourceMaxLen = 128 // DB check constraint; resource strings are host-defined.
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ServiceTokenMarker returns the leading marker that identifies a service token for the given
// application prefix: "<prefix>_st_" when prefix is non-empty, else "st_".
func ServiceTokenMarker(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return serviceTokenTypeSegment
	}
	return prefix + "_" + serviceTokenTypeSegment
}

// HasServiceTokenPrefix reports whether token carries the service-token marker for prefix. Used by
// middleware to route to the service-token path before attempting JWT verification.
func HasServiceTokenPrefix(prefix, token string) bool {
	return strings.HasPrefix(token, ServiceTokenMarker(prefix))
}

// FormatServiceToken assembles the full presented token: <marker><key_id>_<secret>.
func FormatServiceToken(prefix, keyID, secret string) string {
	return ServiceTokenMarker(prefix) + keyID + "_" + secret
}

// ParseServiceToken splits a presented token into its key_id and secret. key_id and
// secret are base62 (no underscores), so the first "_" after the marker is the
// unambiguous delimiter. ok is false if the token lacks the marker or either
// part is empty.
func ParseServiceToken(prefix, token string) (keyID, secret string, ok bool) {
	marker := ServiceTokenMarker(prefix)
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

// ServiceToken is the non-secret metadata view of a service token. The secret is never
// stored or returned after creation.
type ServiceToken struct {
	ID          string
	KeyID       string
	Name        string
	Permissions []string
	Resources   []ServiceTokenResource
	CreatedBy   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// ServiceTokenResource is one opaque, host-defined resource scope carried by
// a service token. AuthKit stores and returns the exact Kind/ID pair but does not
// interpret it. Hosts own resource semantics, including any wildcard-looking IDs
// such as "*".
type ServiceTokenResource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// ResolvedServiceToken is the resource-aware service token resolution result.
type ResolvedServiceToken struct {
	TokenID string
	KeyID   string
	// OrgID is the immutable org uuid — the canonical identifier for
	// persistence and cross-service references. OrgSlug is the mutable
	// human-readable name, for presentation/logging only.
	OrgID       string
	OrgSlug     string
	Permissions []string
	Resources   []ServiceTokenResource
}

// ServiceTokenMintOptions is the resource-aware service token mint request. The token
// format remains unchanged; resources are stored beside the opaque credential.
type ServiceTokenMintOptions struct {
	Name        string
	Permissions []string
	Resources   []ServiceTokenResource
	CreatedBy   string
	ExpiresAt   *time.Time
}

// ResourceScopeAuthorizationRequest is passed to a host callback when the HTTP
// service token mint route receives resource scopes. AuthKit has already validated shape
// and permission no-escalation before this hook runs.
type ResourceScopeAuthorizationRequest struct {
	OrgSlug          string
	ActorUserID      string
	Permissions      []string
	Resources        []ServiceTokenResource
	ActorGlobalAdmin bool
}

// ResourceScopeAuthorizer is an optional host callback for service token resource-scope
// no-escalation. Return an error to deny minting. AuthKit treats resource kinds
// and IDs as opaque and never interprets their semantics itself.
type ResourceScopeAuthorizer func(ctx context.Context, req ResourceScopeAuthorizationRequest) error

func (s *Service) AuthorizeServiceTokenResources(ctx context.Context, req ResourceScopeAuthorizationRequest) error {
	resources, err := normalizeServiceTokenResources(req.Resources)
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

func normalizeServiceTokenResources(in []ServiceTokenResource) ([]ServiceTokenResource, error) {
	if in == nil {
		return []ServiceTokenResource{}, nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]ServiceTokenResource, 0, len(in))
	for _, r := range in {
		kind := strings.TrimSpace(r.Kind)
		id := strings.TrimSpace(r.ID)
		if kind == "" || id == "" || len(kind) > serviceTokenResourceMaxLen || len(id) > serviceTokenResourceMaxLen {
			return nil, errors.New("invalid_resource")
		}
		key := kind + "\x00" + id
		if seen[key] {
			return nil, errors.New("duplicate_resource")
		}
		seen[key] = true
		out = append(out, ServiceTokenResource{Kind: kind, ID: id})
	}
	return out, nil
}

// MintServiceToken inserts a new service token for the org and returns its metadata plus
// the full plaintext token (shown ONCE). permissions must already be authorized
// by the caller (the grant decision lives in the HTTP handler / host hook).
// expiresAt is optional (nil = no expiry) and is capped to ServiceTokenMaxTTL
// when set.
func (s *Service) MintServiceToken(ctx context.Context, orgSlug, name string, permissions []string, createdBy string, expiresAt *time.Time) (ServiceToken, string, error) {
	return s.MintServiceTokenWithOptions(ctx, orgSlug, ServiceTokenMintOptions{
		Name:        name,
		Permissions: permissions,
		CreatedBy:   createdBy,
		ExpiresAt:   expiresAt,
	})
}

// MintServiceTokenWithOptions inserts a new service token using the resource-aware mint
// contract. Permissions and resources must already be authorized by the caller.
func (s *Service) MintServiceTokenWithOptions(ctx context.Context, orgSlug string, opts ServiceTokenMintOptions) (ServiceToken, string, error) {
	if err := s.requirePG(); err != nil {
		return ServiceToken{}, "", err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return ServiceToken{}, "", err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return ServiceToken{}, "", errors.New("missing_name")
	}
	permissions := opts.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	resources, err := normalizeServiceTokenResources(opts.Resources)
	if err != nil {
		return ServiceToken{}, "", err
	}

	now := time.Now().UTC()
	expiresAt := opts.ExpiresAt
	if expiresAt != nil && !expiresAt.After(now) {
		return ServiceToken{}, "", errors.New("invalid_expiry")
	}
	if maxTTL := s.opts.ServiceTokenMaxTTL; maxTTL > 0 {
		capAt := now.Add(maxTTL)
		if expiresAt == nil || expiresAt.After(capAt) {
			expiresAt = &capAt
		}
	}

	secret, err := randBase62(serviceTokenSecretLen)
	if err != nil {
		return ServiceToken{}, "", err
	}
	secretHash := sha256Raw(secret)

	var createdByArg *string
	if v := strings.TrimSpace(opts.CreatedBy); v != "" {
		createdByArg = &v
	}

	// key_id is unique; retry a few times on the (astronomically unlikely)
	// collision rather than failing the request.
	var out ServiceToken
	for attempt := 0; attempt < 5; attempt++ {
		keyID, err := randBase62(serviceTokenKeyIDLen)
		if err != nil {
			return ServiceToken{}, "", err
		}
		tx, err := s.pg.Begin(ctx)
		if err != nil {
			return ServiceToken{}, "", err
		}
		qtx := s.qtx(tx)
		ins, err := qtx.ServiceTokenInsert(ctx, db.ServiceTokenInsertParams{
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
			return ServiceToken{}, "", err
		}
		id := ins.ID
		for _, permission := range dedupeStrings(permissions) {
			if err := qtx.ServiceTokenPermissionInsert(ctx, db.ServiceTokenPermissionInsertParams{ServiceTokenID: id, Permission: permission}); err != nil {
				_ = tx.Rollback(ctx)
				return ServiceToken{}, "", err
			}
		}
		for _, r := range resources {
			if err := qtx.ServiceTokenResourceInsert(ctx, db.ServiceTokenResourceInsertParams{TokenID: id, Kind: r.Kind, ResourceID: r.ID}); err != nil {
				_ = tx.Rollback(ctx)
				return ServiceToken{}, "", err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return ServiceToken{}, "", err
		}
		out = ServiceToken{
			ID:          id,
			KeyID:       keyID,
			Name:        name,
			Permissions: permissions,
			Resources:   resources,
			CreatedBy:   strings.TrimSpace(opts.CreatedBy),
			CreatedAt:   ins.CreatedAt,
			ExpiresAt:   expiresAt,
		}
		return out, FormatServiceToken(s.opts.ServiceTokenPrefix, keyID, secret), nil
	}
	return ServiceToken{}, "", errors.New("key_id_generation_failed")
}

// ListServiceTokens returns metadata for every service token of the org (including
// revoked/expired ones, so an admin can see and clean them up). The secret is
// never returned.
func (s *Service) ListServiceTokens(ctx context.Context, orgSlug string) ([]ServiceToken, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ServiceTokensByOrg(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	var out []ServiceToken
	for _, r := range rows {
		out = append(out, ServiceToken{
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
	if err := s.loadServiceTokenPermissions(ctx, out); err != nil {
		return nil, err
	}
	if err := s.loadServiceTokenResources(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeServiceToken marks the service token revoked. It is scoped to the org so a
// token cannot be revoked from a different org. Returns false if no matching,
// not-already-revoked token exists.
func (s *Service) RevokeServiceToken(ctx context.Context, orgSlug, tokenID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	n, err := s.q.ServiceTokenRevoke(ctx, db.ServiceTokenRevokeParams{ID: strings.TrimSpace(tokenID), OrgID: org.ID})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ResolveServiceToken validates a presented service token (key_id + secret) and returns
// the owning org's current slug and the token's frozen permissions. It performs
// an indexed lookup by key_id, a constant-time secret compare, and revoked /
// expired / org-deleted checks, then best-effort async-touches last_used_at.
func (s *Service) ResolveServiceToken(ctx context.Context, keyID, secret string) (orgSlug string, permissions []string, err error) {
	resolved, err := s.ResolveServiceTokenWithResources(ctx, keyID, secret)
	if err != nil {
		return "", nil, err
	}
	return resolved.OrgSlug, resolved.Permissions, nil
}

// ResolveServiceTokenWithResources validates a presented service token and returns the
// full resource-aware result. Existing tokens with no resources return an empty
// Resources slice and remain org-wide for hosts that use the compatibility
// resolver.
func (s *Service) ResolveServiceTokenWithResources(ctx context.Context, keyID, secret string) (ResolvedServiceToken, error) {
	if err := s.requirePG(); err != nil {
		return ResolvedServiceToken{}, err
	}
	row, err := s.q.ServiceTokenByKeyID(ctx, keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResolvedServiceToken{}, ErrInvalidAccessToken
		}
		return ResolvedServiceToken{}, err
	}

	// Constant-time secret comparison.
	if subtle.ConstantTimeCompare(row.SecretHash, sha256Raw(secret)) != 1 {
		return ResolvedServiceToken{}, ErrInvalidAccessToken
	}
	if row.RevokedAt != nil {
		return ResolvedServiceToken{}, ErrAccessTokenRevoked
	}
	if row.ExpiresAt != nil && !row.ExpiresAt.After(time.Now().UTC()) {
		return ResolvedServiceToken{}, ErrAccessTokenExpired
	}
	if row.OrgDeletedAt != nil {
		return ResolvedServiceToken{}, ErrInvalidAccessToken
	}

	s.touchAccessTokenAsync(row.ID)
	gotPerms, err := s.listServiceTokenPermissions(ctx, row.ID)
	if err != nil {
		return ResolvedServiceToken{}, err
	}
	resources, err := s.listServiceTokenResources(ctx, row.ID)
	if err != nil {
		return ResolvedServiceToken{}, err
	}
	return ResolvedServiceToken{
		TokenID:     row.ID,
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
		_ = s.q.ServiceTokenTouchLastUsed(ctx, id)
	}()
}

func (s *Service) loadServiceTokenPermissions(ctx context.Context, tokens []ServiceToken) error {
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
	rows, err := s.q.ServiceTokenPermissionsByTokenIDs(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if i, ok := byID[r.ServiceTokenID]; ok {
			tokens[i].Permissions = append(tokens[i].Permissions, r.Permission)
		}
	}
	return nil
}

func (s *Service) listServiceTokenPermissions(ctx context.Context, tokenID string) ([]string, error) {
	perms, err := s.q.ServiceTokenPermissionsByTokenID(ctx, strings.TrimSpace(tokenID))
	if err != nil {
		return nil, err
	}
	if perms == nil {
		perms = []string{}
	}
	return perms, nil
}

func (s *Service) loadServiceTokenResources(ctx context.Context, tokens []ServiceToken) error {
	if len(tokens) == 0 {
		return nil
	}
	ids := make([]string, 0, len(tokens))
	byID := make(map[string]int, len(tokens))
	for i := range tokens {
		tokens[i].Resources = []ServiceTokenResource{}
		ids = append(ids, tokens[i].ID)
		byID[tokens[i].ID] = i
	}
	rows, err := s.q.ServiceTokenResourcesByTokenIDs(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if i, ok := byID[r.TokenID]; ok {
			tokens[i].Resources = append(tokens[i].Resources, ServiceTokenResource{Kind: r.Kind, ID: r.ResourceID})
		}
	}
	return nil
}

func (s *Service) listServiceTokenResources(ctx context.Context, tokenID string) ([]ServiceTokenResource, error) {
	rows, err := s.q.ServiceTokenResourcesByTokenID(ctx, strings.TrimSpace(tokenID))
	if err != nil {
		return nil, err
	}
	out := make([]ServiceTokenResource, 0, len(rows))
	for _, r := range rows {
		out = append(out, ServiceTokenResource{Kind: r.Kind, ID: r.ResourceID})
	}
	return out, nil
}
