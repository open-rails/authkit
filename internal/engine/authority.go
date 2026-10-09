package engine

// Shared authority helper (#399). Every checked mutation resolves its group
// and identity here, inside the authority transaction, and applies:
//
//	IDENTITY  the identity is valid and live (every kind, every call)
//	CAP       the identity covers a capability permission in the target group
//	COVER     the identity covers every permission a role confers (no escalation)
//	ACCT      CAP on the root group, outranking the target account on root and
//	          covering its grants in each of its groups
//
// The system skips every rule and never an invariant (last owner, MFA).
// Root is the widest scope: an identity's roles on root count in every group, but
// root's own `root:` permissions count only on root (rbac.Schema.ResolveGrants).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/helpers/auth"
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
		return groupTarget{ID: id, Persona: iam.RootPersona()}, err
	case !isUUID(ref.ID()):
		return groupTarget{}, iam.ErrGroupNotFound
	}
	g, err := db.New(st.q).AuthorityGroup(ctx, ref.ID())
	if errors.Is(err, pgx.ErrNoRows) {
		return groupTarget{}, iam.ErrGroupNotFound
	}
	return groupTargetOf(g), err
}

func groupTargetOf(g db.PermissionGroup) groupTarget {
	return groupTarget{ID: g.ID, Persona: ident.Persona(g.Persona)}
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
func (s *Engine) withGroupMutation(ctx context.Context, a auth.Identity, ref iam.GroupRef, apply func(st *permissionGroupStore, g groupTarget) error) error {
	return s.withGroupMutationIn(ctx, a, nil, ref, apply)
}

// withGroupMutationIn is withGroupMutation inside host, the host's own
// transaction, when set (withAuthorityMutationIn).
func (s *Engine) withGroupMutationIn(ctx context.Context, a auth.Identity, host pgx.Tx, ref iam.GroupRef, apply func(st *permissionGroupStore, g groupTarget) error) error {
	return s.withAuthorityMutationIn(ctx, a, host, func(st *permissionGroupStore) error {
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

// authority is an identity's live authority in one group.
type authority struct {
	who    auth.Identity
	system bool
	grants []string // base grants in the group; none when bound elsewhere
}

// covers is the effective-coverage check: the base grants cover p and every
// ceiling permits it. The system covers everything.
func (a authority) covers(p iam.Perm) bool {
	return a.system || rbac.Covers(a.grants, p) && stateOf(a.who).CeilingCovers(p)
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

// requireActor refuses the zero Identity before any work.
func requireIdentity(a auth.Identity) error {
	if _, ok := iam.StateOf(a); !ok {
		return iam.ErrInsufficientAuthority
	}
	return nil
}

// identityAuthority resolves a's live authority in g (rule IDENTITY). A zero, deleted,
// banned, revoked, expired or disabled identity is
// ErrInsufficientAuthority; one whose bound session or device key is revoked
// (Identity.InSession) is ErrSessionRevoked. An identity bound to another group
// resolves with no grants.
func (s *Engine) identityAuthority(ctx context.Context, st *permissionGroupStore, a auth.Identity, g groupTarget) (authority, error) {
	cs, ok := iam.StateOf(a)
	if !ok {
		return authority{}, iam.ErrInsufficientAuthority
	}
	out := authority{who: a}
	session, _ := cs.Session()
	switch {
	case cs.IsSystem():
		out.system = true
		return out, nil
	case cs.Group() != "" && cs.Group() != g.ID:
		return out, nil // pinned to another group
	case cs.IsAPIKey():
		return s.apiKeyAuthority(ctx, st, out, cs.ID(), g)
	case cs.IsApplication():
		return s.applicationAuthority(ctx, st, out, cs.ID(), g)
	case cs.IsUser():
		return s.userAuthority(ctx, st, out, cs.ID(), session, g)
	}
	return authority{}, iam.ErrInsufficientAuthority
}

// userAuthority is a usable user's grants in g, refused when the sign-in the
// identity is bound to no longer stands.
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
// group. Its authority is bound to that group.
func (s *Engine) applicationAuthority(ctx context.Context, st *permissionGroupStore, out authority, appID string, g groupTarget) (authority, error) {
	if !isUUID(appID) {
		return authority{}, iam.ErrInsufficientAuthority
	}
	control, err := db.New(st.q).AuthorityApplicationGroup(ctx, appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority{}, iam.ErrInsufficientAuthority
	}
	if err != nil || control != g.ID {
		return out, err
	}
	out.grants, err = s.subjectGrants(ctx, st, iam.RemoteApplicationSubject(appID), g.ID)
	return out.withoutMFAGrants(s), err
}

// withoutMFAGrants drops the grants of a machine identity (an API key or an
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
	key, err := db.New(st.q).AuthorityAPIKeyRole(ctx, db.AuthorityAPIKeyRoleParams{ID: keyID, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return authority{}, iam.ErrInsufficientAuthority
	}
	if err != nil || key.PermissionGroupID != g.ID {
		return out, err
	}
	out.grants, err = s.roleGrants(g.Persona, ident.RoleText(key.Role))
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

// roleGrants returns what a catalog role of persona confers, else
// ErrRoleNotAssignable.
func (s *Engine) roleGrants(persona iam.Persona, role iam.Role) ([]string, error) {
	if r, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return r.Permissions, nil
	}
	return nil, fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
}

// requireRoleCover is rule COVER for a role in g.
func (s *Engine) requireRoleCover(ctx context.Context, st *permissionGroupStore, a authority, g groupTarget, role iam.Role) error {
	if a.system {
		return nil
	}
	grants, err := s.roleGrants(g.Persona, role)
	if err != nil {
		return err
	}
	return a.requireCover(grants)
}

// requireHeldRoleCover is rule COVER for the role of a credential being taken
// back. A role this app's catalog no longer declares confers nothing, so it
// needs no cover. A member's role: requireMemberRoleCover.
func (s *Engine) requireHeldRoleCover(ctx context.Context, st *permissionGroupStore, a authority, g groupTarget, role iam.Role) error {
	if err := s.requireRoleCover(ctx, st, a, g, role); err != nil && !errors.Is(err, iam.ErrRoleNotAssignable) {
		return err
	}
	return nil
}

// requireRoleGrant is CAP(capability) plus COVER(role) in g: what assigning,
// revoking or issuing a credential for role through capability requires.
func (s *Engine) requireRoleGrant(ctx context.Context, st *permissionGroupStore, a auth.Identity, g groupTarget, capability iam.Perm, role iam.Role) error {
	auth, err := s.identityAuthority(ctx, st, a, g)
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
// site moderation never outranks a group role the identity does not itself hold.
// On root the identity must also outrank a target holding root grants: a peer,
// whose grants cover the identity's, is refused unless peers is set, so staff
// never ban, delete or edit each other; demoting comes first. Callers apply
// their self-targeting rule first.
func (s *Engine) requireAccount(ctx context.Context, st *permissionGroupStore, a auth.Identity, targetUserID string, p iam.Perm, peers bool) error {
	if err := requireIdentity(a); err != nil || stateOf(a).IsSystem() {
		return err
	}
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return err
	}
	root := groupTarget{ID: rootID, Persona: iam.RootPersona()}
	auth, err := s.identityAuthority(ctx, st, a, root)
	if err != nil {
		return err
	}
	if err := auth.requireCap(p); err != nil {
		return err
	}
	held, err := db.New(st.q).AuthorityUserGroups(ctx, db.AuthorityUserGroupsParams{UserID: targetUserID, RootID: rootID})
	if err != nil {
		return err
	}
	groups := []groupTarget{root}
	for _, g := range held {
		groups = append(groups, groupTargetOf(g))
	}
	for _, g := range groups {
		if g.ID != rootID {
			if auth, err = s.identityAuthority(ctx, st, a, g); err != nil {
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
		if g.ID == rootID && !peers && len(target) > 0 && rbac.CoversAll(target, auth.grants) {
			return iam.ErrAccountAuthorityEscalation // a peer
		}
	}
	return nil
}

// savepoint runs fn so that its failure rolls back only its own writes,
// leaving the enclosing transaction usable for the next batch item. The store
// must be over a transaction; pgx's nested transaction is the savepoint.
func (st *permissionGroupStore) savepoint(ctx context.Context, fn func() error) error {
	tx, ok := st.q.(pgx.Tx)
	if !ok {
		return errors.New("authkit: savepoint outside a transaction")
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(); err != nil {
		if rerr := sp.Rollback(ctx); rerr != nil {
			return errors.Join(err, rerr)
		}
		return err
	}
	return sp.Commit(ctx)
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
