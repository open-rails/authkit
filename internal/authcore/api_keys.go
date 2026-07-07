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

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// API keys: long-lived, revocable shared-secret bearer credentials owned by a
// permission-group (not a person), for machine/automation callers (#111). An
// API key holds exactly ONE role of its group's PERSONA catalog (or a group custom
// role); its effective permissions are resolved FROM that role (the GroupSchema
// catalog / group_custom_roles) at use time, so editing the role updates every
// key that holds it. Permissions are app-defined strings, opaque to authkit. See
// agents #43 (lifecycle) and #111 (permission-groups).

// Token sentinel errors are defined in authkit and re-exported here for
// backward compatibility (so core.X callers and errors.Is checks are unaffected).
var (
	ErrInvalidAccessToken = authkit.ErrInvalidAccessToken
	ErrAccessTokenRevoked = authkit.ErrAccessTokenRevoked
	ErrAccessTokenExpired = authkit.ErrAccessTokenExpired
)

const (
	apiKeyKeyIDLen  = 16 // base62 chars; non-secret public lookup id
	apiKeySecretLen = 43 // base62 chars ~= 256 bits of entropy
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// API-key marker/parse/format helpers are defined in authkit (core-free) and
// re-exported here for backward compatibility.
var (
	APIKeyMarker    = authkit.APIKeyMarker
	HasAPIKeyPrefix = authkit.HasAPIKeyPrefix
	FormatAPIKey    = authkit.FormatAPIKey
	ParseAPIKey     = authkit.ParseAPIKey
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
type APIKey = authkit.APIKey

// ResolvedAPIKey is defined in authkit (core-free) and re-exported here.
type ResolvedAPIKey = authkit.ResolvedAPIKey

// APIKeyMintOptions is the API-key mint request. The key references exactly ONE
// role (Role) that must be valid for the owning group's persona catalog (or a
// group custom role); its permissions are resolved from that role at use time.
type APIKeyMintOptions = authkit.APIKeyMintOptions

func (s *Service) authorizeAPIKeyRoleGrant(ctx context.Context, st *PermissionGroupStore, persona, gid, actorUserID, role string) error {
	return s.authorizeRoleGrant(ctx, st, s.groupSchemaOrDefault(), persona, gid, actorUserID, PermCredentialsManage(persona), role)
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
// (persona, instanceSlug), bound to role, and returns its metadata plus the
// full plaintext token (shown ONCE). The role must be valid for the group's
// persona; no-escalation is enforced by the HTTP handler / host hook. expiresAt is
// optional (nil = no expiry) and is capped to APIKeyMaxTTL when set.
func (s *Service) MintAPIKey(ctx context.Context, persona, instanceSlug, name, role, createdBy string, expiresAt *time.Time) (APIKey, string, error) {
	return s.MintAPIKeyWithOptions(ctx, persona, instanceSlug, APIKeyMintOptions{
		Name:      name,
		Role:      role,
		CreatedBy: createdBy,
		ExpiresAt: expiresAt,
	})
}

// MintAPIKeyWithOptions inserts a new API key. The key references exactly ONE
// role (opts.Role) valid for the owning group's persona; its effective
// permissions are resolved from the role at use time.
func (s *Service) MintAPIKeyWithOptions(ctx context.Context, persona, instanceSlug string, opts APIKeyMintOptions) (APIKey, string, error) {
	if err := s.requirePG(); err != nil {
		return APIKey{}, "", err
	}
	persona = strings.TrimSpace(persona)
	instanceSlug = strings.TrimSpace(instanceSlug)
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return APIKey{}, "", err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return APIKey{}, "", authkit.ErrMissingName
	}
	role := strings.ToLower(strings.TrimSpace(opts.Role))
	if role == "" {
		return APIKey{}, "", authkit.ErrInvalidRole
	}
	// The role must be valid for the group's persona: a catalog role, any role
	// for custom-enabled personas, or an existing group custom role.
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), persona, role) {
		if _, ok, cerr := s.lookupGroupCustomRole(ctx, gid, role); cerr != nil {
			return APIKey{}, "", cerr
		} else if !ok {
			return APIKey{}, "", authkit.ErrUnknownRole
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
	if err := s.authorizeAPIKeyRoleGrant(ctx, st, persona, gid, strings.TrimSpace(opts.CreatedBy), role); err != nil {
		return APIKey{}, "", err
	}

	now := time.Now().UTC()
	expiresAt := opts.ExpiresAt
	if expiresAt != nil && !expiresAt.After(now) {
		return APIKey{}, "", authkit.ErrInvalidExpiry
	}
	if maxTTL := s.cfg.APIKeys.MaxTTL; maxTTL > 0 {
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
		if err := tx.Commit(ctx); err != nil {
			return APIKey{}, "", err
		}
		out = APIKey{
			ID:          id,
			KeyID:       keyID,
			Name:        name,
			Role:        role,
			Permissions: permissions,
			CreatedBy:   strings.TrimSpace(opts.CreatedBy),
			CreatedAt:   createdAt,
			ExpiresAt:   expiresAt,
		}
		return out, FormatAPIKey(s.cfg.APIKeys.Prefix, keyID, secret), nil
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
// addressed by (persona, instanceSlug), including revoked/expired ones. The
// secret is never returned.
func (s *Service) ListAPIKeys(ctx context.Context, persona, instanceSlug string) ([]APIKey, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(instanceSlug))
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
	return out, nil
}

// RevokeAPIKey marks the API key revoked. It is scoped to the group so a token
// cannot be revoked from a different group. Returns false if no matching,
// not-already-revoked token exists.
func (s *Service) RevokeAPIKey(ctx context.Context, persona, instanceSlug, tokenID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(instanceSlug))
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
	resolved, err := s.ResolveAPIKeyDetailed(ctx, keyID, secret)
	if err != nil {
		return "", nil, err
	}
	return resolved.PermissionGroupID, resolved.Permissions, nil
}

// ResolveAPIKeyDetailed validates a presented API key and returns the full
// resolution result (id, key_id, owning group, role, and role-resolved
// permissions).
func (s *Service) ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error) {
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
		instanceSlug string
	)
	err := q.QueryRow(ctx,
		`SELECT t.id::text, t.secret_hash, t.role, t.expires_at, t.revoked_at,
		        pg.id::text, pg.persona, COALESCE(pg.instance_slug, '')
		 FROM profiles.api_keys t
		 JOIN profiles.permission_groups pg ON pg.id = t.permission_group_id
		 WHERE t.key_id = $1`, keyID).
		Scan(&id, &secretHash, &role, &expiresAt, &revokedAt, &groupID, &persona, &instanceSlug)
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

	s.touchAccessTokenAsync(id)
	// Resolve the key's role to its effective permission set AT VERIFY TIME (#111).
	gotPerms, err := s.effectiveGroupRolePermissions(ctx, groupID, persona, role)
	if err != nil {
		return ResolvedAPIKey{}, err
	}
	if gotPerms == nil {
		gotPerms = []string{}
	}
	return ResolvedAPIKey{
		APIKeyID:          id,
		KeyID:             keyID,
		PermissionGroupID: groupID,
		Persona:           persona,
		InstanceSlug:      instanceSlug,
		Role:              role,
		Permissions:       gotPerms,
	}, nil
}

// touchAccessTokenAsync updates last_used_at without blocking the request. A
// failure here is non-critical (auth already succeeded). The write is throttled
// in-query to at most once per 5 minutes per key (the WHERE clause no-ops when
// last_used_at is recent), avoiding a row write on every request without adding
// a read round-trip.
func (s *Service) touchAccessTokenAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q := db.ForSchema(s.pg, s.dbSchema())
		_, _ = q.Exec(ctx, `UPDATE profiles.api_keys SET last_used_at = now() WHERE id = $1::uuid AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`, id)
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
