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
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
)

// API keys (#111): long-lived, revocable bearer credentials owned by a
// permission group, for machine callers. A key holds one catalog role of its
// group; its permissions resolve from that role at use time, so editing the
// role changes every key holding it. Issuance follows rule CRED
// (credential_issuers.go): the creator is recorded and the key dies with the
// creator's authority. The system issues keys with no creator.

// effectiveGroupRolePermissions resolves a catalog role of persona to its
// permissions. The role — not any snapshot — is the source of truth, so
// resolution repeats at use time.
func (s *Engine) effectiveGroupRolePermissions(_ context.Context, _ *permissionGroupStore, _ string, persona iam.Persona, role iam.Role) ([]string, error) {
	if def, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return append([]string(nil), def.Permissions...), nil
	}
	return []string{}, nil
}

// MintAPIKey issues a key holding role in ref: CAP(<p>:credentials:manage)
// plus COVER(role). Only a user or the system issues credentials. The token
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
	role := k.Role
	if role.IsZero() {
		return iam.APIKey{}, "", iam.ErrRoleNotAssignable
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
		// A persona without API keys has none, whoever asks (the system too).
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
			out = iam.APIKey{LookupID: minted.LookupID, Name: name, Role: role, Permissions: ident.Perms(grants), CreatedBy: creator, ExpiresAt: expiresAt}
			row, err := db.New(st.q).APIKeyInsert(ctx, db.APIKeyInsertParams{
				GroupID: g.ID, KeyID: minted.LookupID, SecretHash: minted.SecretHash, Name: name,
				Role: role.Name(), CreatedBy: nullable(creator), ExpiresAt: expiresAt,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				continue // lookup id collision
			}
			if err != nil {
				return err
			}
			out.ID, out.CreatedAt, token = row.ID, row.CreatedAt, minted.Token
			return nil
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
	rows, err := db.New(st.q).APIKeysByGroup(ctx, db.APIKeysByGroupParams{GroupID: g.ID, After: after, PageLimit: int64(p.PageLimit() + 1)})
	if err != nil {
		return iam.ListPage[iam.APIKey]{}, err
	}
	keys := make([]iam.APIKey, len(rows))
	for i, r := range rows {
		keys[i] = iam.APIKey{
			ID: r.ID, LookupID: r.KeyID, Name: r.Name, Role: ident.Role(g.Persona, r.Role), CreatedBy: r.CreatedBy,
			CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
		}
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
		q := db.New(st.q)
		name, err := q.APIKeyRoleForUpdate(ctx, db.APIKeyRoleForUpdateParams{ID: id, GroupID: g.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.requireCredentialRevoke(ctx, st, a, g, iam.PermCredentialsManage(g.Persona), ident.Role(g.Persona, name)); err != nil {
			return err
		}
		if err := q.APIKeyRevoke(ctx, id); err != nil {
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
	k, err := s.q.APIKeyByLookupID(ctx, lookupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyInvalid
	}
	if err != nil {
		return iam.APIKeyPrincipal{}, err
	}
	if !apikey.Matches(k.SecretHash, secret) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyInvalid
	}
	if k.RevokedAt != nil || !k.CreatorLive {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyRevoked
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(time.Now().UTC()) {
		return iam.APIKeyPrincipal{}, iam.ErrAPIKeyExpired
	}
	s.touchAccessTokenAsync(k.ID)
	p := iam.APIKeyPrincipal{ID: k.ID, ExpiresAt: k.ExpiresAt, Group: iam.Group{ID: k.GroupID, Persona: ident.Persona(k.Persona), CreatedAt: k.GroupCreatedAt}}
	p.Role = ident.Role(p.Group.Persona, k.Role)
	sch := s.groupSchemaOrDefault()
	grants := []string{}
	if def, ok := sch.Role(p.Group.Persona, p.Role); ok {
		grants = def.Permissions
	}
	p.Permissions = ident.Perms(grants)
	// A key can present no second factor: a role that came to need MFA (a
	// changed RequireMFA) confers nothing even before the boot sweep revokes it.
	if s.TwoFactorEnabled() && sch.RequiresMFA(grants) {
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
		_ = s.q.APIKeyTouch(ctx, id)
	}()
}

// loadAPIKeyPermissions fills each key's Permissions with its role resolved
// now. Keys sharing a role resolve once.
func (s *Engine) loadAPIKeyPermissions(ctx context.Context, st *permissionGroupStore, g groupTarget, keys []iam.APIKey) error {
	byRole := map[iam.Role][]iam.Perm{}
	for i := range keys {
		perms, ok := byRole[keys[i].Role]
		if !ok {
			var err error
			grants, err := s.effectiveGroupRolePermissions(ctx, st, g.ID, g.Persona, keys[i].Role)
			if err != nil {
				return err
			}
			perms = ident.Perms(grants)
			byRole[keys[i].Role] = perms
		}
		keys[i].Permissions = perms
	}
	return nil
}
