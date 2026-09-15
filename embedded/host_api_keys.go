package embedded

import (
	"context"
	"crypto/rand"
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

func (s *Client) authorizeAPIKeyRoleGrant(ctx context.Context, st *PermissionGroupStore, persona authkit.Persona, gid, actorUserID string, role authkit.Role) error {
	return s.authorizeRoleGrant(ctx, st, s.groupSchemaOrDefault(), persona, gid, actorUserID, PermCredentialsManage(persona), role)
}

// effectiveGroupRolePermissions resolves a role NAME to its effective permission
// set within a permission-group of persona: a catalog role from the schema
// (core.Config), or a per-group custom role from group_custom_roles. The role —
// not any snapshot — is the source of truth, so resolution repeats at use time.
func (s *Client) effectiveGroupRolePermissions(ctx context.Context, st *PermissionGroupStore, groupID string, persona authkit.Persona, role authkit.Role) ([]string, error) {
	sch := s.groupSchemaOrDefault()
	if def, ok := sch.Role(persona, role); ok {
		perms := append([]string(nil), def.Permissions...)
		return perms, nil
	}
	// Not a catalog role: look for a per-group custom role.
	resolver, err := st.CustomRolesFor(ctx, []string{groupID})
	if err != nil {
		return nil, err
	}
	if perms, ok := resolver(groupID, role); ok {
		return append([]string(nil), perms...), nil
	}
	return []string{}, nil
}

// MintAPIKeyWithOptions inserts a new API key. The key references exactly ONE
// role (opts.Role) valid for the owning group's persona; its effective
// permissions are resolved from the role at use time.
func (s *Client) MintAPIKeyWithOptions(ctx context.Context, group authkit.GroupRef, opts APIKeyMintOptions) (APIKey, string, error) {
	if err := s.requirePG(); err != nil {
		return APIKey{}, "", err
	}
	persona := authkit.Persona(strings.TrimSpace(string(group.Persona)))
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return APIKey{}, "", err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return APIKey{}, "", authkit.ErrMissingName
	}
	role := authkit.Role(strings.ToLower(strings.TrimSpace(string(opts.Role))))
	if role == "" {
		return APIKey{}, "", authkit.ErrInvalidRole
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
	for attempt := 0; attempt < 5; attempt++ {
		keyID, err := randBase62(apiKeyKeyIDLen)
		if err != nil {
			return APIKey{}, "", err
		}
		var out APIKey
		err = s.withLockedGroup(ctx, gid, func(st *PermissionGroupStore) error {
			if err := s.requireDefinedGroupRole(ctx, st, gid, persona, role); err != nil {
				return err
			}
			permissions, err := s.effectiveGroupRolePermissions(ctx, st, gid, persona, role)
			if err != nil {
				return err
			}
			if permissions == nil {
				permissions = []string{}
			}
			if err := s.authorizeAPIKeyRoleGrant(ctx, st, persona, gid, strings.TrimSpace(opts.CreatedBy), role); err != nil {
				return err
			}
			var id string
			var createdAt time.Time
			err = st.q.QueryRow(ctx, `INSERT INTO profiles.api_keys(permission_group_id,key_id,secret_hash,name,role,created_by,expires_at)
   VALUES($1::uuid,$2,$3,$4,$5,$6,$7) RETURNING id::text,created_at`, gid, keyID, secretHash, name, role, nullable(strings.TrimSpace(opts.CreatedBy)), expiresAt).Scan(&id, &createdAt)
			if err != nil {
				return err
			}
			out = APIKey{ID: id, KeyID: keyID, Name: name, Role: role, Permissions: permissions, CreatedBy: strings.TrimSpace(opts.CreatedBy), CreatedAt: createdAt, ExpiresAt: expiresAt}
			return nil
		})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, "key_id") {
				continue
			}
			return APIKey{}, "", err
		}
		return out, FormatAPIKey(s.cfg.APIKeys.Prefix, keyID, secret), nil
	}
	return APIKey{}, "", errors.New("key_id_generation_failed")
}

// ListAPIKeys returns metadata for every API key of the permission-group
// addressed by (persona, instanceSlug), including revoked/expired ones. The
// secret is never returned.
func (s *Client) ListAPIKeys(ctx context.Context, group authkit.GroupRef) ([]APIKey, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
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
	if err := s.loadAPIKeyPermissions(ctx, gid, authkit.Persona(strings.TrimSpace(string(group.Persona))), out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeAPIKey marks the API key revoked. It is scoped to the group so a token
// cannot be revoked from a different group. Returns false if no matching,
// not-already-revoked token exists.
func (s *Client) RevokeAPIKey(ctx context.Context, group authkit.GroupRef, tokenID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
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
func (s *Client) ResolveAPIKey(ctx context.Context, keyID, secret string) (groupRef string, permissions []string, err error) {
	resolved, err := s.ResolveAPIKeyDetailed(ctx, keyID, secret)
	if err != nil {
		return "", nil, err
	}
	return resolved.PermissionGroupID, resolved.Permissions, nil
}

// ResolveAPIKeyDetailed validates a presented API key and returns the full
// resolution result (id, key_id, owning group, role, and role-resolved
// permissions).
func (s *Client) ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error) {
	if err := s.requirePG(); err != nil {
		return ResolvedAPIKey{}, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	var (
		id                string
		secretHash        []byte
		role              authkit.Role
		expiresAt         *time.Time
		revokedAt         *time.Time
		groupID           string
		persona           authkit.Persona
		instanceSlug      string
		customPermissions []string
	)
	err := q.QueryRow(ctx,
		`SELECT t.id::text, t.secret_hash, t.role, t.expires_at, t.revoked_at,
		        pg.id::text, pg.persona, COALESCE(pg.instance_slug, ''), r.permissions
		 FROM profiles.api_keys t
		 JOIN profiles.permission_groups pg ON pg.id = t.permission_group_id
 LEFT JOIN profiles.group_custom_roles r ON r.permission_group_id=t.permission_group_id AND r.role=t.role
		 WHERE t.key_id = $1`, keyID).
		Scan(&id, &secretHash, &role, &expiresAt, &revokedAt, &groupID, &persona, &instanceSlug, &customPermissions)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResolvedAPIKey{}, ErrInvalidAccessToken
		}
		return ResolvedAPIKey{}, err
	}

	if !SecretEqual(secretHash, sha256Raw(secret)) {
		return ResolvedAPIKey{}, ErrInvalidAccessToken
	}
	if revokedAt != nil {
		return ResolvedAPIKey{}, ErrAccessTokenRevoked
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return ResolvedAPIKey{}, ErrAccessTokenExpired
	}

	s.touchAccessTokenAsync(id)
	// Key and custom definition were read in the same statement snapshot.
	gotPerms := customPermissions
	if def, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		gotPerms = append([]string(nil), def.Permissions...)
	}
	if gotPerms == nil {
		gotPerms = []string{}
	}
	return ResolvedAPIKey{
		APIKeyID:          id,
		KeyID:             keyID,
		PermissionGroupID: groupID,
		AuthorityIssuer:   s.cfg.Token.Issuer,
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
func (s *Client) touchAccessTokenAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q := db.ForSchema(s.pg, s.dbSchema())
		_, _ = q.Exec(ctx, `UPDATE profiles.api_keys SET last_used_at = now() WHERE id = $1::uuid AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`, id)
	}()
}

// loadAPIKeyPermissions fills each key's Permissions with its ROLE resolved to
// effective permissions (#111). Keys sharing a role resolve once (cached per role).
func (s *Client) loadAPIKeyPermissions(ctx context.Context, groupID string, persona authkit.Persona, tokens []APIKey) error {
	if len(tokens) == 0 {
		return nil
	}
	byRole := map[authkit.Role][]string{}
	for i := range tokens {
		role := tokens[i].Role
		perms, ok := byRole[role]
		if !ok {
			var err error
			perms, err = s.effectiveGroupRolePermissions(ctx, s.groupStore(), groupID, persona, role)
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
