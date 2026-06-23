package authcore

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

	"github.com/open-rails/authkit/authbase"
	"github.com/open-rails/authkit/internal/db"
)

// API keys: long-lived, revocable shared-secret bearer credentials owned by a
// permission-group (not a person), for machine/automation callers (#111). An
// API key holds exactly ONE role of its group's PERSONA catalog (or a group custom
// role); its effective permissions are resolved FROM that role (the GroupSchema
// catalog / group_custom_roles) at use time, so editing the role updates every
// key that holds it. Resource-scope ({Kind,ID}) stays a SEPARATE, orthogonal
// binding. Permissions are app-defined strings, opaque to authkit. See agents
// #43 (lifecycle) and #111 (permission-groups).

// Token sentinel errors are defined in authbase and re-exported here for
// backward compatibility (so core.X callers and errors.Is checks are unaffected).
var (
	ErrInvalidAccessToken = authbase.ErrInvalidAccessToken
	ErrAccessTokenRevoked = authbase.ErrAccessTokenRevoked
	ErrAccessTokenExpired = authbase.ErrAccessTokenExpired
)

const (
	apiKeyKeyIDLen       = 16  // base62 chars; non-secret public lookup id
	apiKeySecretLen      = 43  // base62 chars ~= 256 bits of entropy
	apiKeyResourceMaxLen = 128 // DB check constraint; resource strings are host-defined.
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// API-key marker/parse/format helpers are defined in authbase (core-free) and
// re-exported here for backward compatibility.
var (
	APIKeyMarker    = authbase.APIKeyMarker
	HasAPIKeyPrefix = authbase.HasAPIKeyPrefix
	FormatAPIKey    = authbase.FormatAPIKey
	ParseAPIKey     = authbase.ParseAPIKey
)

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
// stored or returned after creation. Role is the single group role the key
// holds; Permissions is that role's RESOLVED effective permission set (a
// convenience projection — the role is the source of truth, edit it to change
// the key).
type APIKey struct {
	ID          string
	KeyID       string
	Name        string
	Role        string
	Permissions []string
	Resources   []APIKeyResource
	CreatedBy   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// APIKeyResource is one opaque, host-defined resource scope carried by an API
// key. Defined in authbase (core-free) and re-exported here.
type APIKeyResource = authbase.APIKeyResource

// ResolvedAPIKey is defined in authbase (core-free) and re-exported here.
type ResolvedAPIKey = authbase.ResolvedAPIKey

// APIKeyMintOptions is the resource-aware API-key mint request. The key
// references exactly ONE role (Role) that must be valid for the owning group's
// persona catalog (or a group custom role); its permissions are resolved from that
// role at use time. Resource-scope is a separate binding.
type APIKeyMintOptions struct {
	Name      string
	Role      string
	Resources []APIKeyResource
	CreatedBy string
	ExpiresAt *time.Time
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

// effectiveGroupRolePermissions resolves a role NAME to its effective permission
// set within a permission-group of persona: a catalog role from the schema
// (core.Config), or a per-group custom role from group_custom_roles. The role —
// not any snapshot — is the source of truth, so resolution repeats at use time.
func (s *Service) effectiveGroupRolePermissions(ctx context.Context, groupID, persona, role string) ([]string, error) {
	sch := s.groupSchemaOrDefault()
	if def, ok := sch.Role(persona, role); ok {
		perms := append([]string(nil), def.Permissions...)
		return perms, nil
	}
	// Not a catalog role: look for a per-group custom role.
	resolver, err := s.groupStore().CustomRolesFor(ctx, []string{groupID})
	if err != nil {
		return nil, err
	}
	if perms, ok := resolver(groupID, role); ok {
		return append([]string(nil), perms...), nil
	}
	return []string{}, nil
}

// MintAPIKey inserts a new API key for the permission-group addressed by
// (persona, resourceSlug), bound to role, and returns its metadata plus the
// full plaintext token (shown ONCE). The role must be valid for the group's
// persona; no-escalation is enforced by the HTTP handler / host hook. expiresAt is
// optional (nil = no expiry) and is capped to APIKeyMaxTTL when set.
func (s *Service) MintAPIKey(ctx context.Context, persona, resourceSlug, name, role, createdBy string, expiresAt *time.Time) (APIKey, string, error) {
	return s.MintAPIKeyWithOptions(ctx, persona, resourceSlug, APIKeyMintOptions{
		Name:      name,
		Role:      role,
		CreatedBy: createdBy,
		ExpiresAt: expiresAt,
	})
}

// MintAPIKeyWithOptions inserts a new API key using the resource-aware mint
// contract. The key references exactly ONE role (opts.Role) valid for the owning
// group's TYPE; its effective permissions are resolved from the role at use
// time. No-escalation is the caller's responsibility. Resources are a separate
// binding.
func (s *Service) MintAPIKeyWithOptions(ctx context.Context, persona, resourceSlug string, opts APIKeyMintOptions) (APIKey, string, error) {
	if err := s.requirePG(); err != nil {
		return APIKey{}, "", err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(resourceSlug))
	if err != nil {
		return APIKey{}, "", err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return APIKey{}, "", errors.New("missing_name")
	}
	role := strings.ToLower(strings.TrimSpace(opts.Role))
	if role == "" {
		return APIKey{}, "", errors.New("invalid_role")
	}
	// The role must be valid for the group's persona: a catalog role, any role
	// for custom-enabled personas, or an existing group custom role.
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), persona, role) {
		if _, ok, cerr := s.lookupGroupCustomRole(ctx, gid, role); cerr != nil {
			return APIKey{}, "", cerr
		} else if !ok {
			return APIKey{}, "", errors.New("unknown_role")
		}
	}
	// Resolve the role's effective permissions for the returned view.
	permissions, err := s.effectiveGroupRolePermissions(ctx, gid, persona, role)
	if err != nil {
		return APIKey{}, "", err
	}
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
		q := db.ForSchema(tx, s.dbSchema())
		var id string
		var createdAt time.Time
		err = q.QueryRow(ctx,
			`INSERT INTO profiles.api_keys
			   (permission_group_id, key_id, secret_hash, name, role, created_by, expires_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
			 RETURNING id::text, created_at`,
			gid, keyID, secretHash, name, role, createdByArg, expiresAt).Scan(&id, &createdAt)
		if err != nil {
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, "key_id") {
				continue // key_id collision; regenerate
			}
			return APIKey{}, "", err
		}
		for _, r := range resources {
			if _, err := q.Exec(ctx,
				`INSERT INTO profiles.api_key_resources (api_key_id, kind, resource_id)
				 VALUES ($1::uuid, $2, $3)`, id, r.Kind, r.ID); err != nil {
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
			Role:        role,
			Permissions: permissions,
			Resources:   resources,
			CreatedBy:   strings.TrimSpace(opts.CreatedBy),
			CreatedAt:   createdAt,
			ExpiresAt:   expiresAt,
		}
		return out, FormatAPIKey(s.opts.APIKeyPrefix, keyID, secret), nil
	}
	return APIKey{}, "", errors.New("key_id_generation_failed")
}

// lookupGroupCustomRole reports whether role is an existing per-group custom
// role and returns its permissions.
func (s *Service) lookupGroupCustomRole(ctx context.Context, groupID, role string) ([]string, bool, error) {
	resolver, err := s.groupStore().CustomRolesFor(ctx, []string{groupID})
	if err != nil {
		return nil, false, err
	}
	perms, ok := resolver(groupID, role)
	return perms, ok, nil
}

// ListAPIKeys returns metadata for every API key of the permission-group
// addressed by (persona, resourceSlug), including revoked/expired ones. The
// secret is never returned.
func (s *Service) ListAPIKeys(ctx context.Context, persona, resourceSlug string) ([]APIKey, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(resourceSlug))
	if err != nil {
		return nil, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT id::text, key_id, name, role, COALESCE(created_by::text, ''),
		        created_at, last_used_at, expires_at, revoked_at
		 FROM profiles.api_keys
		 WHERE permission_group_id = $1::uuid
		 ORDER BY created_at DESC`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.KeyID, &k.Name, &k.Role, &k.CreatedBy,
			&k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.loadAPIKeyPermissions(ctx, gid, persona, out); err != nil {
		return nil, err
	}
	if err := s.loadAPIKeyResources(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeAPIKey marks the API key revoked. It is scoped to the group so a token
// cannot be revoked from a different group. Returns false if no matching,
// not-already-revoked token exists.
func (s *Service) RevokeAPIKey(ctx context.Context, persona, resourceSlug, tokenID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(resourceSlug))
	if err != nil {
		return false, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.api_keys SET revoked_at = now()
		 WHERE id = $1::uuid AND permission_group_id = $2::uuid AND revoked_at IS NULL`,
		strings.TrimSpace(tokenID), gid)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ResolveAPIKey validates a presented API key (key_id + secret) and returns the
// owning permission-group id and the key's
// effective permissions resolved from its role at verify time (a role edit is
// reflected immediately — perms are never frozen into the key).
func (s *Service) ResolveAPIKey(ctx context.Context, keyID, secret string) (groupRef string, permissions []string, err error) {
	resolved, err := s.ResolveAPIKeyWithResources(ctx, keyID, secret)
	if err != nil {
		return "", nil, err
	}
	return resolved.PermissionGroupID, resolved.Permissions, nil
}

// ResolveAPIKeyWithResources validates a presented API key and returns the full
// resource-aware result.
func (s *Service) ResolveAPIKeyWithResources(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error) {
	if err := s.requirePG(); err != nil {
		return ResolvedAPIKey{}, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	var (
		id           string
		secretHash   []byte
		role         string
		expiresAt    *time.Time
		revokedAt    *time.Time
		groupID      string
		persona      string
		groupDeleted *time.Time
	)
	err := q.QueryRow(ctx,
		`SELECT t.id::text, t.secret_hash, t.role, t.expires_at, t.revoked_at,
		        pg.id::text, pg.persona, pg.deleted_at
		 FROM profiles.api_keys t
		 JOIN profiles.permission_groups pg ON pg.id = t.permission_group_id
		 WHERE t.key_id = $1`, keyID).
		Scan(&id, &secretHash, &role, &expiresAt, &revokedAt, &groupID, &persona, &groupDeleted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResolvedAPIKey{}, ErrInvalidAccessToken
		}
		return ResolvedAPIKey{}, err
	}

	// Constant-time secret comparison.
	if subtle.ConstantTimeCompare(secretHash, sha256Raw(secret)) != 1 {
		return ResolvedAPIKey{}, ErrInvalidAccessToken
	}
	if revokedAt != nil {
		return ResolvedAPIKey{}, ErrAccessTokenRevoked
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return ResolvedAPIKey{}, ErrAccessTokenExpired
	}
	if groupDeleted != nil {
		return ResolvedAPIKey{}, ErrInvalidAccessToken
	}

	s.touchAccessTokenAsync(id)
	// Resolve the key's role to its effective permission set AT VERIFY TIME (#111).
	gotPerms, err := s.effectiveGroupRolePermissions(ctx, groupID, persona, role)
	if err != nil {
		return ResolvedAPIKey{}, err
	}
	if gotPerms == nil {
		gotPerms = []string{}
	}
	resources, err := s.listAPIKeyResources(ctx, id)
	if err != nil {
		return ResolvedAPIKey{}, err
	}
	return ResolvedAPIKey{
		APIKeyID:          id,
		KeyID:             keyID,
		PermissionGroupID: groupID,
		Role:              role,
		Permissions:       gotPerms,
		Resources:         resources,
	}, nil
}

// touchAccessTokenAsync updates last_used_at without blocking the request. A
// failure here is non-critical (auth already succeeded).
func (s *Service) touchAccessTokenAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q := db.ForSchema(s.pg, s.dbSchema())
		_, _ = q.Exec(ctx, `UPDATE profiles.api_keys SET last_used_at = now() WHERE id = $1::uuid`, id)
	}()
}

// loadAPIKeyPermissions fills each key's Permissions with its ROLE resolved to
// effective permissions (#111). Keys sharing a role resolve once (cached per role).
func (s *Service) loadAPIKeyPermissions(ctx context.Context, groupID, persona string, tokens []APIKey) error {
	if len(tokens) == 0 {
		return nil
	}
	byRole := map[string][]string{}
	for i := range tokens {
		role := tokens[i].Role
		perms, ok := byRole[role]
		if !ok {
			var err error
			perms, err = s.effectiveGroupRolePermissions(ctx, groupID, persona, role)
			if err != nil {
				return err
			}
			if perms == nil {
				perms = []string{}
			}
			byRole[role] = perms
		}
		tokens[i].Permissions = perms
	}
	return nil
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
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT api_key_id::text, kind, resource_id FROM profiles.api_key_resources
		 WHERE api_key_id = ANY($1::uuid[])`, ids)
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
			tokens[i].Resources = append(tokens[i].Resources, APIKeyResource{Kind: kind, ID: resourceID})
		}
	}
	return rows.Err()
}

func (s *Service) listAPIKeyResources(ctx context.Context, tokenID string) ([]APIKeyResource, error) {
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT kind, resource_id FROM profiles.api_key_resources WHERE api_key_id = $1::uuid`,
		strings.TrimSpace(tokenID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]APIKeyResource, 0)
	for rows.Next() {
		var kind, resourceID string
		if err := rows.Scan(&kind, &resourceID); err != nil {
			return nil, err
		}
		out = append(out, APIKeyResource{Kind: kind, ID: resourceID})
	}
	return out, rows.Err()
}
