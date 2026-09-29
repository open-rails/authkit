package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/apikey"
	"github.com/open-rails/authkit/internal/errmodel"
)

// API keys (#111): long-lived, revocable bearer credentials owned by a
// permission group, for machine callers. A key holds one role of its group
// (catalog or custom); its permissions resolve from that role at use time, so
// editing the role changes every key holding it. Issuance follows rule CRED
// (credential_issuers.go): the creator is recorded and the key dies with the
// creator's authority. The operator issues keys with no creator.

// effectiveGroupRolePermissions resolves a role NAME to its effective permission
// set within a permission-group of persona: a catalog role from the schema
// (core.Config), or a per-group custom role from group_custom_roles. The role —
// not any snapshot — is the source of truth, so resolution repeats at use time.
func (s *Engine) effectiveGroupRolePermissions(ctx context.Context, st *permissionGroupStore, groupID string, persona iam.Persona, role iam.Role) ([]string, error) {
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

// MintAPIKey issues a key holding role in ref: CAP(<p>:credentials:manage)
// plus COVER(role). Only a user or the operator issues credentials. The token
// is returned once.
func (s *Engine) MintAPIKey(ctx context.Context, a iam.Actor, ref iam.GroupRef, k iam.NewAPIKey) (iam.APIKey, string, error) {
	creator, err := credentialIssuer(a)
	if err != nil {
		return iam.APIKey{}, "", err
	}
	name := strings.TrimSpace(k.Name)
	if name == "" {
		return iam.APIKey{}, "", errmodel.ErrMissingName
	}
	role := iam.Role(strings.ToLower(strings.TrimSpace(string(k.Role))))
	if role == "" {
		return iam.APIKey{}, "", errmodel.ErrInvalidRole
	}
	now := time.Now().UTC()
	expiresAt := k.ExpiresAt
	if expiresAt != nil && !expiresAt.After(now) {
		return iam.APIKey{}, "", errmodel.ErrInvalidExpiry
	}
	if maxTTL := s.cfg.APIKeys.MaxTTL; maxTTL > 0 {
		capAt := now.Add(maxTTL)
		if expiresAt == nil || expiresAt.After(capAt) {
			expiresAt = &capAt
		}
	}
	var out iam.APIKey
	var token string
	err = s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		// A persona without API keys has none, whoever asks (the operator too).
		if p, ok := s.groupSchemaOrDefault().Persona(g.Persona); !ok || !p.APIKeys {
			return fmt.Errorf("persona %q does not enable API keys: %w", g.Persona, iam.ErrInsufficientAuthority)
		}
		if err := s.requireDefinedGroupRole(ctx, st, g.ID, g.Persona, role); err != nil {
			return err
		}
		grants, err := s.roleGrants(ctx, st, g, role)
		if err != nil {
			return err
		}
		if err := s.refuseMFACredential(role, grants); err != nil {
			return err
		}
		if err := s.requireRoleGrant(ctx, st, a, g, iam.PermCredentialsManage(g.Persona), role); err != nil {
			return err
		}
		for range 5 {
			minted, err := apikey.Mint(s.cfg.APIKeys.Prefix)
			if err != nil {
				return err
			}
			out = iam.APIKey{LookupID: minted.LookupID, Name: name, Role: role, Permissions: append([]string{}, grants...), CreatedBy: creator, ExpiresAt: expiresAt}
			err = st.q.QueryRow(ctx, `INSERT INTO api_keys(permission_group_id,key_id,secret_hash,name,role,created_by,expires_at)
 VALUES($1::uuid,$2,$3,$4,$5,$6,$7) ON CONFLICT (key_id) DO NOTHING RETURNING id::text,created_at`,
				g.ID, minted.LookupID, minted.SecretHash, name, role, nullable(creator), expiresAt).Scan(&out.ID, &out.CreatedAt)
			if errors.Is(err, pgx.ErrNoRows) {
				continue // lookup id collision
			}
			token = minted.Token
			return err
		}
		return errors.New("authkit: api key lookup id generation failed")
	})
	if err != nil {
		return iam.APIKey{}, "", err
	}
	return out, token, nil
}

// APIKeys lists the group's keys, newest first, including revoked and
// expired ones (terminal keys are purged after 90 days). Never the secret.
func (s *Engine) APIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error) {
	if err := s.requirePG(); err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	after, err := idCursor(p)
	if err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	rows, err := st.q.Query(ctx, `SELECT id::text, key_id, name, role, COALESCE(created_by::text,''), created_at, last_used_at, expires_at, revoked_at
 FROM api_keys WHERE permission_group_id=$1::uuid AND ($2::uuid IS NULL OR id<$2::uuid)
 ORDER BY id DESC LIMIT $3`, g.ID, after, p.PageLimit()+1)
	if err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (iam.APIKey, error) {
		var k iam.APIKey
		err := row.Scan(&k.ID, &k.LookupID, &k.Name, &k.Role, &k.CreatedBy, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt)
		return k, err
	})
	if err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	page := idPage(keys, p.PageLimit(), func(k iam.APIKey) string { return k.ID })
	if err := s.loadAPIKeyPermissions(ctx, st, g, page.Items); err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	return page, nil
}

// RevokeAPIKey revokes the group's live key id. It needs the authority to
// issue the key's role: CAP(<p>:credentials:manage) plus COVER(role). False
// means no live key matched in the group.
func (s *Engine) RevokeAPIKey(ctx context.Context, a iam.Actor, ref iam.GroupRef, id string) (bool, error) {
	if err := requireActor(a); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	revoked := false
	err := s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !isUUID(id) {
			return nil
		}
		var role iam.Role
		err := st.q.QueryRow(ctx, `SELECT role FROM api_keys WHERE id=$1::uuid AND permission_group_id=$2::uuid AND revoked_at IS NULL FOR UPDATE`, id, g.ID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.requireCredentialRevoke(ctx, st, a, g, iam.PermCredentialsManage(g.Persona), role); err != nil {
			return err
		}
		if _, err := st.q.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1::uuid`, id); err != nil {
			return err
		}
		revoked = true
		return nil
	})
	return revoked, err
}

// ResolveAPIKey authenticates a presented token: the key must exist with a
// matching secret, be neither revoked nor expired, belong to a live group, and
// have a live creator (a banned, deleted or reserved creator's keys are
// refused even before any sweep revokes them). Permissions are the role's now.
// It is verify's API-key resolver.
func (s *Engine) ResolveAPIKey(ctx context.Context, token string) (iam.APIKeyPrincipal, error) {
	if err := s.requirePG(); err != nil {
		return iam.APIKeyPrincipal{}, err
	}
	lookupID, secret, ok := apikey.Parse(s.cfg.APIKeys.Prefix, strings.TrimSpace(token))
	if !ok {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyInvalid
	}
	var (
		p           iam.APIKeyPrincipal
		secretHash  []byte
		revokedAt   *time.Time
		creatorLive bool
		custom      []string
	)
	err := s.pg.QueryRow(ctx, `SELECT k.id::text, k.secret_hash, k.role, k.expires_at, k.revoked_at, `+issuerLive("k.created_by")+`,
        g.id::text, g.persona, COALESCE(g.instance_slug,''), g.display_name, r.permissions
 FROM api_keys k
 JOIN permission_groups g ON g.id=k.permission_group_id
 LEFT JOIN group_custom_roles r ON r.permission_group_id=k.permission_group_id AND r.role=k.role
 WHERE k.key_id=$1 AND g.deleted_at IS NULL`, lookupID).
		Scan(&p.ID, &secretHash, &p.Role, &p.ExpiresAt, &revokedAt, &creatorLive,
			&p.Group.ID, &p.Group.Persona, &p.Group.Slug, &p.Group.DisplayName, &custom)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyInvalid
	}
	if err != nil {
		return iam.APIKeyPrincipal{}, err
	}
	if !apikey.Matches(secretHash, secret) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyInvalid
	}
	if revokedAt != nil || !creatorLive {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyRevoked
	}
	if p.ExpiresAt != nil && !p.ExpiresAt.After(time.Now().UTC()) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyExpired
	}
	s.touchAccessTokenAsync(p.ID)
	sch := s.groupSchemaOrDefault()
	persona, _ := sch.Persona(p.Group.Persona)
	switch def, ok := sch.Role(p.Group.Persona, p.Role); {
	case ok:
		p.Permissions = append([]string{}, def.Permissions...)
	case custom != nil && persona.CustomRoles:
		p.Permissions = custom
	default:
		p.Permissions = []string{}
	}
	// A key can present no second factor: a role that came to need MFA (a
	// changed RequireMFA) confers nothing even before the boot sweep revokes it.
	if s.TwoFactorEnabled() && sch.RequiresMFA(p.Permissions) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyRevoked
	}
	p.LookupID = lookupID
	p.Issuer = s.cfg.Token.Issuer
	return p, nil
}

// touchAccessTokenAsync updates last_used_at without blocking the request. A
// failure here is non-critical (auth already succeeded). The write is throttled
// in-query to at most once per 5 minutes per key (the WHERE clause no-ops when
// last_used_at is recent), avoiding a row write on every request without adding
// a read round-trip.
func (s *Engine) touchAccessTokenAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q := s.pg
		_, _ = q.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1::uuid AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`, id)
	}()
}

// loadAPIKeyPermissions fills each key's Permissions with its role resolved
// now. Keys sharing a role resolve once.
func (s *Engine) loadAPIKeyPermissions(ctx context.Context, st *permissionGroupStore, g groupTarget, keys []iam.APIKey) error {
	byRole := map[iam.Role][]string{}
	for i := range keys {
		perms, ok := byRole[keys[i].Role]
		if !ok {
			var err error
			if perms, err = s.effectiveGroupRolePermissions(ctx, st, g.ID, g.Persona, keys[i].Role); err != nil {
				return err
			}
			byRole[keys[i].Role] = perms
		}
		keys[i].Permissions = perms
	}
	return nil
}
