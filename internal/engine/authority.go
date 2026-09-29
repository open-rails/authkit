package engine

// Shared authority helper (#399). Every checked mutation resolves its group
// and actor here, inside the authority transaction, and applies:
//
//	ACTOR  the actor is valid and live (every kind, every call)
//	CAP    the actor covers a capability permission in the target group
//	COVER  the actor covers every permission a role confers (no escalation)
//	ACCT   CAP on the root group plus coverage of the target account's root grants
//
// The system skips every rule and never an invariant (last owner, MFA).
// Root is the widest scope: an actor's roles on root count in every group, but
// root's own `root:` permissions count only on root (rbac.Schema.ResolveGrants).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// groupTarget is a GroupRef resolved to a live group. Persona is the stored
// persona; capability permissions derive from it, never from the caller.
type groupTarget struct {
	ID      string
	Persona iam.Persona
}

// resolveGroup resolves ref to a live group through st (call it inside the
// authority transaction): by id, or the root group, whose id is cached.
func (s *Engine) resolveGroup(ctx context.Context, st *permissionGroupStore, ref iam.GroupRef) (groupTarget, error) {
	switch {
	case ref.IsRoot():
		id, err := s.rootGroup(ctx, st)
		return groupTarget{ID: id, Persona: iam.RootPersona}, err
	case !isUUID(ref.ID()):
		return groupTarget{}, iam.ErrGroupNotFound
	}
	var g groupTarget
	err := st.q.QueryRow(ctx, `SELECT id::text, persona FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL`, ref.ID()).Scan(&g.ID, scanPersona(&g.Persona))
	if errors.Is(err, pgx.ErrNoRows) {
		return groupTarget{}, iam.ErrGroupNotFound
	}
	return g, err
}

// rootGroup returns the root group id, cached once read. A root created here
// is not cached: the enclosing transaction may still roll back.
func (s *Engine) rootGroup(ctx context.Context, st *permissionGroupStore) (string, error) {
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
func (s *Engine) withGroupMutation(ctx context.Context, a iam.Actor, ref iam.GroupRef, apply func(st *permissionGroupStore, g groupTarget) error) error {
	return s.withAuthorityMutation(ctx, a, func(st *permissionGroupStore) error {
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
	actor  iam.Actor
	system bool
	grants []string // base grants in the group; none when bound elsewhere
}

// covers is the effective-coverage check: the base grants cover p and every
// ceiling permits it. The system covers everything.
func (a authority) covers(p iam.Perm) bool {
	return a.system || rbac.Covers(a.grants, p) && a.actor.CeilingCovers(p)
}

func (a authority) coversAll(grants []string) bool {
	for _, g := range grants {
		if !a.covers(ident.Perm(g)) {
			return false
		}
	}
	return true
}

// requireCap is rule CAP.
func (a authority) requireCap(p iam.Perm) error {
	if !a.covers(p) {
		return iam.ErrInsufficientAuthority
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
		return iam.ErrInsufficientAuthority
	}
	return nil
}

// actorAuthority resolves a's live authority in g (rule ACTOR). A zero, deleted,
// reserved, banned, revoked, expired or disabled actor is
// ErrInsufficientAuthority; one whose bound session or device key is revoked
// (Actor.InSession) is ErrSessionRevoked. An actor bound to another group
// resolves with no grants, as does a delegation from a foreign issuer.
func (s *Engine) actorAuthority(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget) (authority, error) {
	out := authority{actor: a}
	session, _ := a.Session()
	switch a.Kind() {
	case iam.ActorSystem:
		out.system = true
		return out, nil
	case iam.ActorUser:
		return s.userAuthority(ctx, st, out, a.ID(), session, g)
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
			return s.userAuthority(ctx, st, out, grant.Subject, session, g)
		}
		return out, nil
	}
	return authority{}, iam.ErrInsufficientAuthority
}

// userAuthority is a usable user's grants in g, refused when the sign-in the
// actor is bound to no longer stands.
func (s *Engine) userAuthority(ctx context.Context, st *permissionGroupStore, out authority, userID string, session iam.SessionRef, g groupTarget) (authority, error) {
	usable, signedIn, err := userLive(ctx, st.q, userID, session)
	switch {
	case err != nil:
		return authority{}, err
	case !signedIn:
		return authority{}, iam.ErrSessionRevoked
	case !usable:
		return authority{}, iam.ErrInsufficientAuthority
	}
	out.grants, err = s.subjectGrants(ctx, st, iam.UserSubject(userID), g.ID)
	return out, err
}

// applicationAuthority resolves an enabled application in a live controlling
// group. Its authority is bound to that group; wantGroup, when set, must match it.
func (s *Engine) applicationAuthority(ctx context.Context, st *permissionGroupStore, out authority, appID, wantGroup string, g groupTarget) (authority, error) {
	if !isUUID(appID) {
		return authority{}, iam.ErrInsufficientAuthority
	}
	var control string
	err := st.q.QueryRow(ctx, `SELECT a.permission_group_id::text FROM remote_applications a JOIN permission_groups g ON g.id=a.permission_group_id
 WHERE a.id=$1::uuid AND a.enabled AND g.deleted_at IS NULL AND `+registrarLive("a"), appID).Scan(&control)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && wantGroup != "" && wantGroup != control {
		return authority{}, iam.ErrInsufficientAuthority
	}
	if err != nil || control != g.ID {
		return out, err
	}
	out.grants, err = s.subjectGrants(ctx, st, iam.RemoteApplicationSubject(appID), g.ID)
	return out.withoutMFAGrants(s), err
}

// withoutMFAGrants drops the grants of a machine actor (an API key or an
// application) that reach a permission needing MFA: it can present no second
// factor, whatever path handed it the role.
func (a authority) withoutMFAGrants(s *Engine) authority {
	if s.TwoFactorEnabled() && s.groupSchemaOrDefault().RequiresMFA(a.grants) {
		a.grants = nil
	}
	return a
}

// apiKeyAuthority resolves a live key of a live creator: the permissions of
// its role, bound to its group.
func (s *Engine) apiKeyAuthority(ctx context.Context, st *permissionGroupStore, out authority, keyID string, g groupTarget) (authority, error) {
	if !isUUID(keyID) {
		return authority{}, iam.ErrInsufficientAuthority
	}
	var gid string
	var role iam.Role
	err := st.q.QueryRow(ctx, `SELECT k.permission_group_id::text, k.role FROM api_keys k JOIN permission_groups g ON g.id=k.permission_group_id
 WHERE k.id=$1::uuid AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND g.deleted_at IS NULL AND `+issuerLive("k.created_by"), keyID).Scan(&gid, scanRole(&role, g.Persona))
	if errors.Is(err, pgx.ErrNoRows) {
		return authority{}, iam.ErrInsufficientAuthority
	}
	if err != nil || gid != g.ID {
		return out, err
	}
	out.grants, err = s.roleGrants(ctx, st, g, role)
	if errors.Is(err, iam.ErrRoleNotAssignable) {
		return out, nil
	}
	return out.withoutMFAGrants(s), err
}

// subjectGrants is the subject's walk-up union of grants in gid.
func (s *Engine) subjectGrants(ctx context.Context, st *permissionGroupStore, subject iam.Subject, gid string) ([]string, error) {
	asg, err := st.WalkAssignments(ctx, gid, subject)
	if err != nil {
		return nil, err
	}
	return s.groupSchemaOrDefault().ResolveGrants(gid, asg), nil
}

// roleGrants returns what a catalog role confers in g, else
// ErrRoleNotAssignable.
func (s *Engine) roleGrants(_ context.Context, _ *permissionGroupStore, g groupTarget, role iam.Role) ([]string, error) {
	if r, ok := s.groupSchemaOrDefault().Role(g.Persona, role); ok {
		return r.Permissions, nil
	}
	return nil, fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
}

// requireRoleCover is rule COVER for a role in g.
func (s *Engine) requireRoleCover(ctx context.Context, st *permissionGroupStore, a authority, g groupTarget, role iam.Role) error {
	if a.system {
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
func (s *Engine) requireRoleGrant(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, capability iam.Perm, role iam.Role) error {
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
func (s *Engine) requireAccount(ctx context.Context, st *permissionGroupStore, a iam.Actor, targetUserID string, p iam.Perm) error {
	if err := requireActor(a); err != nil || a.Kind() == iam.ActorSystem {
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
		if err := rows.Scan(&g.ID, scanPersona(&g.Persona)); err != nil {
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

// canonicalUUID is s as the lower-case hyphenated uuid PostgreSQL returns; ok
// is false for anything else. Ids are compared only in this form, so a
// differently cased id never slips past a self rule (N6).
func canonicalUUID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !isUUID(s) {
		return "", false
	}
	return strings.ToLower(s), true
}
