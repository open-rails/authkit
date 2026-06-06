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
)

// Organization Access Tokens (OATs): long-lived, revocable bearer credentials
// owned by an org (not a person), for machine/automation callers. An OAT carries
// a set of app-defined PERMISSION strings (opaque to authkit; the embedding app
// defines and enforces what each one means). See agents #43 (lifecycle) and #44
// (permission model).

var (
	// ErrInvalidAccessToken indicates an OAT that does not exist, has a bad
	// secret, or whose owning org is gone. Deliberately indistinguishable from
	// a malformed token so callers learn nothing from the error.
	ErrInvalidAccessToken = errors.New("invalid_token")
	// ErrAccessTokenRevoked indicates the OAT was explicitly revoked.
	ErrAccessTokenRevoked = errors.New("token_revoked")
	// ErrAccessTokenExpired indicates the OAT is past its expires_at.
	ErrAccessTokenExpired = errors.New("token_expired")
)

const (
	// oatTypeSegment is the FIXED, non-configurable type tag. The full marker is
	// "<app>_oat_" when an app prefix is set, or bare "oat_" when it is empty.
	oatTypeSegment    = "oat_"
	oatKeyIDLen       = 16  // base62 chars; non-secret public lookup id
	oatSecretLen      = 43  // base62 chars ~= 256 bits of entropy
	oatResourceMaxLen = 128 // DB check constraint; resource strings are host-defined.
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// OATMarker returns the leading marker that identifies an OAT for the given
// application prefix: "<prefix>_oat_" when prefix is non-empty, else "oat_".
func OATMarker(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return oatTypeSegment
	}
	return prefix + "_" + oatTypeSegment
}

// HasOATPrefix reports whether token carries the OAT marker for prefix. Used by
// middleware to route to the OAT path before attempting JWT verification.
func HasOATPrefix(prefix, token string) bool {
	return strings.HasPrefix(token, OATMarker(prefix))
}

// FormatOAT assembles the full presented token: <marker><key_id>_<secret>.
func FormatOAT(prefix, keyID, secret string) string {
	return OATMarker(prefix) + keyID + "_" + secret
}

// ParseOAT splits a presented token into its key_id and secret. key_id and
// secret are base62 (no underscores), so the first "_" after the marker is the
// unambiguous delimiter. ok is false if the token lacks the marker or either
// part is empty.
func ParseOAT(prefix, token string) (keyID, secret string, ok bool) {
	marker := OATMarker(prefix)
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

// OrgAccessToken is the non-secret metadata view of an OAT. The secret is never
// stored or returned after creation.
type OrgAccessToken struct {
	ID          string
	KeyID       string
	Name        string
	Permissions []string
	Resources   []OrgAccessTokenResource
	CreatedBy   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// OrgAccessTokenResource is one opaque, host-defined resource scope carried by
// an OAT. AuthKit stores and returns the exact Kind/ID pair but does not
// interpret it. Hosts own resource semantics, including any wildcard-looking IDs
// such as "*".
type OrgAccessTokenResource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// ResolvedOrgAccessToken is the resource-aware OAT resolution result.
type ResolvedOrgAccessToken struct {
	TokenID     string
	KeyID       string
	OrgSlug     string
	Permissions []string
	Resources   []OrgAccessTokenResource
}

// OrgAccessTokenMintOptions is the resource-aware OAT mint request. The token
// format remains unchanged; resources are stored beside the opaque credential.
type OrgAccessTokenMintOptions struct {
	Name        string
	Permissions []string
	Resources   []OrgAccessTokenResource
	CreatedBy   string
	ExpiresAt   *time.Time
}

// ResourceScopeAuthorizationRequest is passed to a host callback when the HTTP
// OAT mint route receives resource scopes. AuthKit has already validated shape
// and permission no-escalation before this hook runs.
type ResourceScopeAuthorizationRequest struct {
	OrgSlug          string
	ActorUserID      string
	Permissions      []string
	Resources        []OrgAccessTokenResource
	ActorGlobalAdmin bool
}

// ResourceScopeAuthorizer is an optional host callback for OAT resource-scope
// no-escalation. Return an error to deny minting. AuthKit treats resource kinds
// and IDs as opaque and never interprets their semantics itself.
type ResourceScopeAuthorizer func(ctx context.Context, req ResourceScopeAuthorizationRequest) error

func (s *Service) AuthorizeOrgAccessTokenResources(ctx context.Context, req ResourceScopeAuthorizationRequest) error {
	resources, err := normalizeOrgAccessTokenResources(req.Resources)
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

func normalizeOrgAccessTokenResources(in []OrgAccessTokenResource) ([]OrgAccessTokenResource, error) {
	if in == nil {
		return []OrgAccessTokenResource{}, nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]OrgAccessTokenResource, 0, len(in))
	for _, r := range in {
		kind := strings.TrimSpace(r.Kind)
		id := strings.TrimSpace(r.ID)
		if kind == "" || id == "" || len(kind) > oatResourceMaxLen || len(id) > oatResourceMaxLen {
			return nil, errors.New("invalid_resource")
		}
		key := kind + "\x00" + id
		if seen[key] {
			return nil, errors.New("duplicate_resource")
		}
		seen[key] = true
		out = append(out, OrgAccessTokenResource{Kind: kind, ID: id})
	}
	return out, nil
}

// MintOrgAccessToken inserts a new OAT for the org and returns its metadata plus
// the full plaintext token (shown ONCE). permissions must already be authorized
// by the caller (the grant decision lives in the HTTP handler / host hook).
// expiresAt is optional (nil = no expiry) and is capped to OrgAccessTokenMaxTTL
// when set.
func (s *Service) MintOrgAccessToken(ctx context.Context, orgSlug, name string, permissions []string, createdBy string, expiresAt *time.Time) (OrgAccessToken, string, error) {
	return s.MintOrgAccessTokenWithOptions(ctx, orgSlug, OrgAccessTokenMintOptions{
		Name:        name,
		Permissions: permissions,
		CreatedBy:   createdBy,
		ExpiresAt:   expiresAt,
	})
}

// MintOrgAccessTokenWithOptions inserts a new OAT using the resource-aware mint
// contract. Permissions and resources must already be authorized by the caller.
func (s *Service) MintOrgAccessTokenWithOptions(ctx context.Context, orgSlug string, opts OrgAccessTokenMintOptions) (OrgAccessToken, string, error) {
	if err := s.requirePG(); err != nil {
		return OrgAccessToken{}, "", err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return OrgAccessToken{}, "", err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return OrgAccessToken{}, "", errors.New("missing_name")
	}
	permissions := opts.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	resources, err := normalizeOrgAccessTokenResources(opts.Resources)
	if err != nil {
		return OrgAccessToken{}, "", err
	}

	now := time.Now().UTC()
	expiresAt := opts.ExpiresAt
	if expiresAt != nil && !expiresAt.After(now) {
		return OrgAccessToken{}, "", errors.New("invalid_expiry")
	}
	if maxTTL := s.opts.OrgAccessTokenMaxTTL; maxTTL > 0 {
		capAt := now.Add(maxTTL)
		if expiresAt == nil || expiresAt.After(capAt) {
			expiresAt = &capAt
		}
	}

	secret, err := randBase62(oatSecretLen)
	if err != nil {
		return OrgAccessToken{}, "", err
	}
	secretHash := sha256Raw(secret)

	var createdByArg any
	if strings.TrimSpace(opts.CreatedBy) != "" {
		createdByArg = strings.TrimSpace(opts.CreatedBy)
	}

	// key_id is unique; retry a few times on the (astronomically unlikely)
	// collision rather than failing the request.
	var out OrgAccessToken
	for attempt := 0; attempt < 5; attempt++ {
		keyID, err := randBase62(oatKeyIDLen)
		if err != nil {
			return OrgAccessToken{}, "", err
		}
		var id string
		var createdAt time.Time
		tx, err := s.pg.Begin(ctx)
		if err != nil {
			return OrgAccessToken{}, "", err
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO profiles.org_access_tokens
			  (org_id, key_id, secret_hash, name, permissions, created_by, expires_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid, $7)
			RETURNING id::text, created_at
		`, org.ID, keyID, secretHash, name, permissions, createdByArg, expiresAt).Scan(&id, &createdAt)
		if err != nil {
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, "key_id") {
				continue // key_id collision; regenerate
			}
			return OrgAccessToken{}, "", err
		}
		for _, r := range resources {
			if _, err := tx.Exec(ctx, `
				INSERT INTO profiles.org_access_token_resources (token_id, kind, resource_id)
				VALUES ($1::uuid, $2, $3)
			`, id, r.Kind, r.ID); err != nil {
				_ = tx.Rollback(ctx)
				return OrgAccessToken{}, "", err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return OrgAccessToken{}, "", err
		}
		out = OrgAccessToken{
			ID:          id,
			KeyID:       keyID,
			Name:        name,
			Permissions: permissions,
			Resources:   resources,
			CreatedBy:   strings.TrimSpace(opts.CreatedBy),
			CreatedAt:   createdAt,
			ExpiresAt:   expiresAt,
		}
		return out, FormatOAT(s.opts.TokenPrefix, keyID, secret), nil
	}
	return OrgAccessToken{}, "", errors.New("key_id_generation_failed")
}

// ListOrgAccessTokens returns metadata for every OAT of the org (including
// revoked/expired ones, so an admin can see and clean them up). The secret is
// never returned.
func (s *Service) ListOrgAccessTokens(ctx context.Context, orgSlug string) ([]OrgAccessToken, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT id::text, key_id, name, permissions, COALESCE(created_by::text, ''),
		       created_at, last_used_at, expires_at, revoked_at
		FROM profiles.org_access_tokens
		WHERE org_id=$1::uuid
		ORDER BY created_at DESC
	`, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgAccessToken
	for rows.Next() {
		var t OrgAccessToken
		if err := rows.Scan(&t.ID, &t.KeyID, &t.Name, &t.Permissions, &t.CreatedBy,
			&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		if t.Permissions == nil {
			t.Permissions = []string{}
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.loadOrgAccessTokenResources(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeOrgAccessToken marks the OAT revoked. It is scoped to the org so a
// token cannot be revoked from a different org. Returns false if no matching,
// not-already-revoked token exists.
func (s *Service) RevokeOrgAccessToken(ctx context.Context, orgSlug, tokenID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	tag, err := s.pg.Exec(ctx, `
		UPDATE profiles.org_access_tokens
		SET revoked_at=now()
		WHERE id=$1::uuid AND org_id=$2::uuid AND revoked_at IS NULL
	`, strings.TrimSpace(tokenID), org.ID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ResolveOrgAccessToken validates a presented OAT (key_id + secret) and returns
// the owning org's current slug and the token's frozen permissions. It performs
// an indexed lookup by key_id, a constant-time secret compare, and revoked /
// expired / org-deleted checks, then best-effort async-touches last_used_at.
func (s *Service) ResolveOrgAccessToken(ctx context.Context, keyID, secret string) (orgSlug string, permissions []string, err error) {
	resolved, err := s.ResolveOrgAccessTokenWithResources(ctx, keyID, secret)
	if err != nil {
		return "", nil, err
	}
	return resolved.OrgSlug, resolved.Permissions, nil
}

// ResolveOrgAccessTokenWithResources validates a presented OAT and returns the
// full resource-aware result. Existing tokens with no resources return an empty
// Resources slice and remain org-wide for hosts that use the compatibility
// resolver.
func (s *Service) ResolveOrgAccessTokenWithResources(ctx context.Context, keyID, secret string) (ResolvedOrgAccessToken, error) {
	if err := s.requirePG(); err != nil {
		return ResolvedOrgAccessToken{}, err
	}
	var (
		err        error
		id         string
		secretHash []byte
		gotPerms   []string
		expiresAt  *time.Time
		revokedAt  *time.Time
		slug       string
		orgDeleted *time.Time
	)
	err = s.pg.QueryRow(ctx, `
		SELECT t.id::text, t.secret_hash, t.permissions, t.expires_at, t.revoked_at,
		       o.slug, o.deleted_at
		FROM profiles.org_access_tokens t
		JOIN profiles.orgs o ON o.id = t.org_id
		WHERE t.key_id = $1
	`, keyID).Scan(&id, &secretHash, &gotPerms, &expiresAt, &revokedAt, &slug, &orgDeleted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResolvedOrgAccessToken{}, ErrInvalidAccessToken
		}
		return ResolvedOrgAccessToken{}, err
	}

	// Constant-time secret comparison.
	if subtle.ConstantTimeCompare(secretHash, sha256Raw(secret)) != 1 {
		return ResolvedOrgAccessToken{}, ErrInvalidAccessToken
	}
	if revokedAt != nil {
		return ResolvedOrgAccessToken{}, ErrAccessTokenRevoked
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return ResolvedOrgAccessToken{}, ErrAccessTokenExpired
	}
	if orgDeleted != nil {
		return ResolvedOrgAccessToken{}, ErrInvalidAccessToken
	}

	s.touchAccessTokenAsync(id)
	if gotPerms == nil {
		gotPerms = []string{}
	}
	resources, err := s.listOrgAccessTokenResources(ctx, id)
	if err != nil {
		return ResolvedOrgAccessToken{}, err
	}
	return ResolvedOrgAccessToken{
		TokenID:     id,
		KeyID:       keyID,
		OrgSlug:     slug,
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
		_, _ = s.pg.Exec(ctx, `UPDATE profiles.org_access_tokens SET last_used_at=now() WHERE id=$1::uuid`, id)
	}()
}

func (s *Service) loadOrgAccessTokenResources(ctx context.Context, tokens []OrgAccessToken) error {
	if len(tokens) == 0 {
		return nil
	}
	ids := make([]string, 0, len(tokens))
	byID := make(map[string]int, len(tokens))
	for i := range tokens {
		tokens[i].Resources = []OrgAccessTokenResource{}
		ids = append(ids, tokens[i].ID)
		byID[tokens[i].ID] = i
	}
	rows, err := s.pg.Query(ctx, `
		SELECT token_id::text, kind, resource_id
		FROM profiles.org_access_token_resources
		WHERE token_id = ANY($1::uuid[])
		ORDER BY token_id::text, kind, resource_id
	`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tokenID, kind, resourceID string
		if err := rows.Scan(&tokenID, &kind, &resourceID); err != nil {
			return err
		}
		if i, ok := byID[tokenID]; ok {
			tokens[i].Resources = append(tokens[i].Resources, OrgAccessTokenResource{Kind: kind, ID: resourceID})
		}
	}
	return rows.Err()
}

func (s *Service) listOrgAccessTokenResources(ctx context.Context, tokenID string) ([]OrgAccessTokenResource, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT kind, resource_id
		FROM profiles.org_access_token_resources
		WHERE token_id=$1::uuid
		ORDER BY kind, resource_id
	`, strings.TrimSpace(tokenID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgAccessTokenResource{}
	for rows.Next() {
		var r OrgAccessTokenResource
		if err := rows.Scan(&r.Kind, &r.ID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
