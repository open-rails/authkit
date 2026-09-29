package engine

// Permission groups: the compiled role schema, the root singleton and live
// permission checks.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// PermissionGroupSchema returns the compiled Config.Roles.
func (s *Engine) PermissionGroupSchema() *rbac.Schema {
	return s.groupSchemaOrDefault()
}

var rootOnlySchema = rbac.Default()

func (s *Engine) groupSchemaOrDefault() *rbac.Schema {
	if s.groupSchema != nil {
		return s.groupSchema
	}
	return rootOnlySchema
}

// KnownPermission reports whether perm is registered in a persona catalog.
func (s *Engine) KnownPermission(perm iam.Perm) bool {
	return s.groupSchemaOrDefault().KnownPermission(perm)
}

// groupStore binds a PermissionGroupStore to the engine's schema-bound pool
// handle, so unqualified SQL resolves to the configured namespace (authkit #69).
func (s *Engine) groupStore() *permissionGroupStore {
	return s.groupStoreFor(s.pg)
}

// groupStoreFor is a store over q that records its events in q, the change's
// transaction; set actor to the one making the change.
func (s *Engine) groupStoreFor(q db.DBTX) *permissionGroupStore {
	st := newPermissionGroupStore(q)
	st.now = s.namingNow
	st.emit = func(ctx context.Context, a iam.Actor, events ...iam.Event) error {
		return s.emitEvents(ctx, q, a, events...)
	}
	return st
}

// initializeGroups installs the root singleton. It never assigns users roles
// or restores revoked authority. The shared authority lock and transaction
// keep concurrent construction atomic.
func (s *Engine) initializeGroups(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	if err := s.withAuthorityMutation(ctx, iam.Actor{}, func(st *permissionGroupStore) error {
		_, err := st.ensureRootGroup(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("authkit: initialize permission groups (apply migrations before New): %w", err)
	}
	s.logRBACDrift(ctx)
	return nil
}

func (s *Engine) logRBACDrift(ctx context.Context) {
	if report, err := s.driftReport(ctx); err == nil && report.Total() > 0 {
		slog.Default().Warn("authkit: rbac drift detected",
			"group_user_roles", report.GroupUserRoles,
			"api_keys", report.APIKeys,
		)
	}
}

// ensureRootGroup creates the singleton root group if absent (idempotent) and
// returns its internal id. Concurrent cold boots race the singleton index; the
// loser adopts the winner's row instead of failing (#258).
func (s *Engine) ensureRootGroup(ctx context.Context) (string, error) {
	return s.groupStore().ensureRootGroup(ctx)
}

func (st *permissionGroupStore) ensureRootGroup(ctx context.Context) (string, error) {
	id, err := st.RootGroupID(ctx)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, iam.ErrGroupNotFound) {
		return "", err
	}
	// DO NOTHING keeps a concurrent singleton insert from aborting a caller's
	// enclosing transaction. Root has no mutable name claim.
	err = st.q.QueryRow(ctx, `INSERT INTO permission_groups (persona)
		VALUES ('root') ON CONFLICT DO NOTHING RETURNING id::text`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return st.RootGroupID(ctx)
	}
	return id, err
}

// validRoleForPersona reports whether role is a catalog role of persona.
func (s *Engine) validRoleForPersona(sch *rbac.Schema, persona iam.Persona, role iam.Role) bool {
	if role.IsZero() {
		return false
	}
	_, ok := sch.Role(persona, role)
	return ok
}

// Can reports whether a covers perm in the group ref addresses, live: a dead
// actor, an unknown group or an actor bound to another group is false, and an
// actor whose bound session was revoked is ErrSessionRevoked. The system is
// always true. An unregistered perm is ErrUnknownPermission.
func (s *Engine) Can(ctx context.Context, a iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	if !s.KnownPermission(perm) {
		return false, fmt.Errorf("%w: %q", iam.ErrUnknownPermission, perm)
	}
	if a.IsZero() {
		return false, nil
	}
	if err := s.requirePG(); err != nil {
		return false, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if errors.Is(err, iam.ErrGroupNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	auth, err := s.actorAuthority(ctx, st, a, g)
	if errors.Is(err, iam.ErrInsufficientAuthority) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return auth.covers(perm), nil
}

// EffectivePermissions returns a's effective grant patterns per group id, for
// clients that gate UI on permission strings (glob-matching with
// iam.Perm.Matches). Globs are returned verbatim; a ceiling narrows them.
// Unknown and deleted groups and groups granting nothing are absent; a dead
// actor has none, and one whose bound session was revoked is
// ErrSessionRevoked. The system gets each persona's owner grant. A user's
// grants on many groups are read in one query.
func (s *Engine) EffectivePermissions(ctx context.Context, a iam.Actor, refs []iam.GroupRef) (map[string][]iam.Perm, error) {
	if len(refs) > iam.MaxBatch {
		return nil, fmt.Errorf("batch has %d groups; at most %d", len(refs), iam.MaxBatch)
	}
	out := map[string][]iam.Perm{}
	if a.IsZero() || len(refs) == 0 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	st := s.groupStore()
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		if !ref.IsRoot() {
			if u, err := uuid.Parse(ref.ID()); err == nil {
				ids = append(ids, u.String())
			}
			continue
		}
		g, err := s.resolveGroup(ctx, st, ref)
		if errors.Is(err, iam.ErrGroupNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, g.ID)
	}
	if userID, ok := s.actorUser(a); ok {
		session, _ := a.Session()
		usable, signedIn, err := userLive(ctx, st.q, userID, session)
		switch {
		case err != nil:
			return nil, err
		case !signedIn:
			return nil, iam.ErrSessionRevoked
		case !usable:
			return out, nil
		}
		subject := iam.UserSubject(userID)
		byGroup, err := st.GrantsOnGroups(ctx, s.groupSchemaOrDefault(), subject, ids)
		if err != nil {
			return nil, err
		}
		for gid, grants := range byGroup {
			if perms := s.effectiveGrants(authority{actor: a, grants: grants}, groupTarget{ID: gid}); len(perms) > 0 {
				out[gid] = perms
			}
		}
		return out, nil
	}
	groups, err := st.groupsByID(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.DeletedAt != nil {
			continue
		}
		t := groupTarget{ID: g.ID, Persona: g.Persona}
		auth, err := s.actorAuthority(ctx, st, a, t)
		if errors.Is(err, iam.ErrInsufficientAuthority) {
			return map[string][]iam.Perm{}, nil
		}
		if err != nil {
			return nil, err
		}
		if perms := s.effectiveGrants(auth, t); len(perms) > 0 {
			out[g.ID] = perms
		}
	}
	return out, nil
}

// actorUser is the user whose grants a acts with: a user, or a delegation
// this deployment issued for one.
func (s *Engine) actorUser(a iam.Actor) (string, bool) {
	switch a.Kind() {
	case iam.ActorUser:
		return a.ID(), true
	case iam.ActorDelegated:
		grant, _ := a.Delegation()
		return grant.Subject, grant.RemoteApplicationID == "" && grant.Issuer == strings.TrimSpace(s.cfg.Token.Issuer)
	}
	return "", false
}

// effectiveGrants is auth's grants narrowed by its ceiling: a grant the
// ceiling fully permits stays a pattern; otherwise only the catalog
// permissions it names that the ceiling permits remain.
func (s *Engine) effectiveGrants(auth authority, g groupTarget) []iam.Perm {
	if auth.system {
		return []iam.Perm{g.Persona.OwnerGrant()}
	}
	sch := s.groupSchemaOrDefault()
	var out []iam.Perm
	seen := map[iam.Perm]bool{}
	add := func(p iam.Perm) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, raw := range auth.grants {
		grant := ident.Perm(raw)
		if auth.actor.CeilingCovers(grant) {
			add(grant)
			continue
		}
		persona, _ := sch.Persona(grant.Persona())
		for _, perm := range persona.Permissions {
			if perm.Matches(grant) && auth.actor.CeilingCovers(perm) {
				add(perm)
			}
		}
	}
	return out
}

// refuseMFACredential: an API key cannot present a second factor, so it may
// not carry a role whose permissions need one.
func (s *Engine) refuseMFACredential(role iam.Role, grants []string) error {
	if s.TwoFactorEnabled() && s.groupSchemaOrDefault().RequiresMFA(grants) {
		return fmt.Errorf("role %q needs MFA, which an API key cannot provide: %w", role, iam.ErrRoleNotAssignable)
	}
	return nil
}
