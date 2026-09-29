package authkit

// Shared authority helper (#399). Every checked mutation resolves its group
// and actor here, inside the authority transaction, and applies:
//
//	ACTOR  the actor is valid and live (every kind, every call)
//	CAP    the actor covers a capability permission in the target group
//	COVER  the actor covers every permission a role confers (no escalation)
//	ACCT   CAP on the root group plus coverage of the target account's root grants
//
// An operator skips every rule and never an invariant (last owner, MFA).
// Root is the widest scope: an actor's roles on root count in every group, but
// root's own `root:` permissions count only on root (iam.GroupSchema.ResolveGrants).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
)

// groupTarget is a GroupRef resolved to a live group. Persona is the stored
// persona; capability permissions derive from it, never from the caller.
type groupTarget struct {
	ID      string
	Persona iam.Persona
	Slug    string
}

// resolveGroup resolves ref to a live group through st (call it inside the
// authority transaction): by id, by persona and slug (request binding and
// tombstone forwarding apply), or the root group, whose id is cached.
func (s *engine) resolveGroup(ctx context.Context, st *permissionGroupStore, ref iam.GroupRef) (groupTarget, error) {
	var id string
	switch {
	case ref.IsZero():
		return groupTarget{}, iam.ErrGroupNotFound
	case ref.IsRoot():
		id, err := s.rootGroup(ctx, st)
		return groupTarget{ID: id, Persona: iam.RootPersona}, err
	case ref.ID() != "":
		if !isUUID(ref.ID()) {
			return groupTarget{}, iam.ErrGroupNotFound
		}
		id = ref.ID()
	default:
		if err := iam.ValidateGroupInstanceSlug(ref); err != nil {
			return groupTarget{}, err
		}
		var err error
		if id, err = st.GroupByInstanceSlug(ctx, ref); err != nil {
			return groupTarget{}, err
		}
	}
	var g groupTarget
	err := st.q.QueryRow(ctx, `SELECT id::text, persona, COALESCE(instance_slug,'') FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL`, id).Scan(&g.ID, &g.Persona, &g.Slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return groupTarget{}, iam.ErrGroupNotFound
	}
	return g, err
}

// rootGroup returns the root group id, cached once read. A root created here
// is not cached: the enclosing transaction may still roll back.
func (s *engine) rootGroup(ctx context.Context, st *permissionGroupStore) (string, error) {
	if id, _ := s.rootGroupID.Load().(string); id != "" {
		return id, nil
	}
	id, err := st.RootGroupID(ctx)
	if errors.Is(err, iam.ErrGroupNotFound) {
		return st.ensureRootGroup(ctx)
	}
	if err != nil {
		return "", err
	}
	s.rootGroupID.Store(id)
	return id, nil
}

// withGroupMutation runs apply in one authority transaction (advisory lock,
// ReadCommitted, credential re-check before commit) with ref resolved and its
// row locked.
func (s *engine) withGroupMutation(ctx context.Context, ref iam.GroupRef, apply func(st *permissionGroupStore, g groupTarget) error) error {
	return s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		g, err := s.resolveGroup(ctx, st, ref)
		if err != nil {
			return err
		}
		if err := lockPermissionGroup(ctx, st.q, g.ID); err != nil {
			return err
		}
		return apply(st, g)
	})
}

// authority is an actor's live authority in one group.
type authority struct {
	actor    iam.Actor
	operator bool
	grants   []string // base grants in the group; none when bound elsewhere
}

// covers is the effective-coverage check: the base grants cover p and every
// ceiling permits it. An operator covers everything.
func (a authority) covers(p iam.Perm) bool {
	return a.operator || iam.AnyGrantCovers(a.grants, p) && a.actor.CeilingCovers(p)
}

func (a authority) coversAll(grants []string) bool {
	for _, g := range grants {
		if !a.covers(iam.Perm(g)) {
			return false
		}
	}
	return true
}

// requireCap is rule CAP.
func (a authority) requireCap(p iam.Perm) error {
	if !a.covers(p) {
		return iam.ErrInsufficientRoleAuthority
	}
	return nil
}

// requireCover is rule COVER over explicit grants.
func (a authority) requireCover(grants []string) error {
	if !a.coversAll(grants) {
		return iam.ErrRoleAssignmentEscalation
	}
	return nil
}

// requireActor refuses the zero Actor before any work.
func requireActor(a iam.Actor) error {
	if a.IsZero() {
		return iam.ErrInsufficientRoleAuthority
	}
	return nil
}

// actorAuthority resolves a's live authority in g (rule ACTOR). A zero, deleted,
// reserved, banned, revoked, expired or disabled actor is
// ErrInsufficientRoleAuthority. An actor bound to another group resolves with
// no grants, as does a delegation from a foreign issuer.
func (s *engine) actorAuthority(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget) (authority, error) {
	out := authority{actor: a}
	switch a.Kind() {
	case iam.ActorOperator:
		out.operator = true
		return out, nil
	case iam.ActorUser:
		return s.userAuthority(ctx, st, out, a.ID(), g)
	case iam.ActorRemoteApplication:
		return s.applicationAuthority(ctx, st, out, a.ID(), "", g)
	case iam.ActorAPIKey:
		return s.apiKeyAuthority(ctx, st, out, a.ID(), g)
	case iam.ActorDelegated:
		grant, _ := a.Delegation()
		switch {
		case grant.RemoteApplicationID != "":
			return s.applicationAuthority(ctx, st, out, grant.RemoteApplicationID, grant.GroupID, g)
		case grant.Issuer == strings.TrimSpace(s.cfg.Token.Issuer):
			return s.userAuthority(ctx, st, out, grant.Subject, g)
		}
		return out, nil
	}
	return authority{}, iam.ErrInsufficientRoleAuthority
}

func (s *engine) userAuthority(ctx context.Context, st *permissionGroupStore, out authority, userID string, g groupTarget) (authority, error) {
	subject := iam.UserSubject(userID)
	if !isUUID(userID) {
		return authority{}, iam.ErrInsufficientRoleAuthority
	}
	live, err := subjectUsable(ctx, st.q, subject)
	if err != nil {
		return authority{}, err
	}
	if !live {
		return authority{}, iam.ErrInsufficientRoleAuthority
	}
	out.grants, err = s.subjectGrants(ctx, st, subject, g.ID)
	return out, err
}

// applicationAuthority resolves an enabled application in a live controlling
// group. Its authority is bound to that group; wantGroup, when set, must match it.
func (s *engine) applicationAuthority(ctx context.Context, st *permissionGroupStore, out authority, appID, wantGroup string, g groupTarget) (authority, error) {
	if !isUUID(appID) {
		return authority{}, iam.ErrInsufficientRoleAuthority
	}
	var control string
	err := st.q.QueryRow(ctx, `SELECT a.permission_group_id::text FROM remote_applications a JOIN permission_groups g ON g.id=a.permission_group_id
 WHERE a.id=$1::uuid AND a.enabled AND g.deleted_at IS NULL`, appID).Scan(&control)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && wantGroup != "" && wantGroup != control {
		return authority{}, iam.ErrInsufficientRoleAuthority
	}
	if err != nil || control != g.ID {
		return out, err
	}
	out.grants, err = s.subjectGrants(ctx, st, iam.RemoteApplicationSubject(appID), g.ID)
	return out, err
}

// apiKeyAuthority resolves a live key: the permissions of its role, bound to its group.
func (s *engine) apiKeyAuthority(ctx context.Context, st *permissionGroupStore, out authority, keyID string, g groupTarget) (authority, error) {
	if !isUUID(keyID) {
		return authority{}, iam.ErrInsufficientRoleAuthority
	}
	var gid string
	var role iam.Role
	err := st.q.QueryRow(ctx, `SELECT k.permission_group_id::text, k.role FROM api_keys k JOIN permission_groups g ON g.id=k.permission_group_id
 WHERE k.id=$1::uuid AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND g.deleted_at IS NULL`, keyID).Scan(&gid, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority{}, iam.ErrInsufficientRoleAuthority
	}
	if err != nil || gid != g.ID {
		return out, err
	}
	out.grants, err = s.roleGrants(ctx, st, g, role)
	if errors.Is(err, iam.ErrRoleNotAssignable) {
		return out, nil
	}
	return out, err
}

// subjectGrants is the subject's walk-up union of grants in gid, custom roles included.
func (s *engine) subjectGrants(ctx context.Context, st *permissionGroupStore, subject iam.Subject, gid string) ([]string, error) {
	asg, resolver, err := st.assignmentsWithCustomRoles(ctx, gid, subject, true)
	if err != nil {
		return nil, err
	}
	return s.groupSchemaOrDefault().ResolveGrants(gid, asg, resolver), nil
}

// roleGrants returns what role confers in g: a catalog role's permissions or a
// custom role's stored grants, else ErrRoleNotAssignable.
func (s *engine) roleGrants(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role) ([]string, error) {
	sch := s.groupSchemaOrDefault()
	if r, ok := sch.Role(g.Persona, role); ok {
		return r.Permissions, nil
	}
	if td, ok := sch.Persona(g.Persona); ok && td.CustomRoles {
		resolver, err := st.CustomRolesFor(ctx, []string{g.ID})
		if err != nil {
			return nil, err
		}
		if grants, ok := resolver(g.ID, role); ok {
			return grants, nil
		}
	}
	return nil, fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
}

// requireRoleCover is rule COVER for a role in g.
func (s *engine) requireRoleCover(ctx context.Context, st *permissionGroupStore, a authority, g groupTarget, role iam.Role) error {
	if a.operator {
		return nil
	}
	grants, err := s.roleGrants(ctx, st, g, role)
	if err != nil {
		return err
	}
	return a.requireCover(grants)
}

// requireRoleGrant is CAP(capability) plus COVER(role) in g: what assigning,
// revoking or issuing a credential for role through capability requires.
func (s *engine) requireRoleGrant(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, capability iam.Perm, role iam.Role) error {
	auth, err := s.actorAuthority(ctx, st, a, g)
	if err != nil {
		return err
	}
	if err := auth.requireCap(capability); err != nil {
		return err
	}
	return s.requireRoleCover(ctx, st, auth, g, role)
}

// requireAccount is rule ACCT(p) over targetUserID: CAP(p) on the root group,
// and, in root and in every group where the target holds a role, coverage of
// the target's effective grants there (else ErrAccountAuthorityEscalation), so
// site moderation never outranks a group role the actor does not itself hold.
// Callers apply their self-targeting rule first.
func (s *engine) requireAccount(ctx context.Context, st *permissionGroupStore, a iam.Actor, targetUserID string, p iam.Perm) error {
	if err := requireActor(a); err != nil || a.Kind() == iam.ActorOperator {
		return err
	}
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return err
	}
	root := groupTarget{ID: rootID, Persona: iam.RootPersona}
	auth, err := s.actorAuthority(ctx, st, a, root)
	if err != nil {
		return err
	}
	if err := auth.requireCap(p); err != nil {
		return err
	}
	groups := []groupTarget{root}
	rows, err := st.q.Query(ctx, `SELECT g.id::text, g.persona FROM group_user_roles r JOIN permission_groups g ON g.id=r.permission_group_id
 WHERE r.user_id=$1::uuid AND g.id<>$2::uuid AND g.deleted_at IS NULL ORDER BY g.id`, targetUserID, rootID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var g groupTarget
		if err := rows.Scan(&g.ID, &g.Persona); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, g := range groups {
		if g.ID != rootID {
			if auth, err = s.actorAuthority(ctx, st, a, g); err != nil {
				return err
			}
		}
		target, err := s.subjectGrants(ctx, st, iam.UserSubject(targetUserID), g.ID)
		if err != nil {
			return err
		}
		if !auth.coversAll(target) {
			return iam.ErrAccountAuthorityEscalation
		}
	}
	return nil
}

// savepoint runs fn so that its failure rolls back only its own writes,
// leaving the enclosing transaction usable for the next batch item.
func (st *permissionGroupStore) savepoint(ctx context.Context, fn func() error) error {
	if _, err := st.q.Exec(ctx, `SAVEPOINT authkit_item`); err != nil {
		return err
	}
	if err := fn(); err != nil {
		if _, rerr := st.q.Exec(ctx, `ROLLBACK TO SAVEPOINT authkit_item`); rerr != nil {
			return errors.Join(err, rerr)
		}
		return err
	}
	_, err := st.q.Exec(ctx, `RELEASE SAVEPOINT authkit_item`)
	return err
}

// isUUID reports whether s is a hyphenated uuid (any case), so a malformed id
// never reaches a ::uuid cast.
func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil && len(s) == 36
}
