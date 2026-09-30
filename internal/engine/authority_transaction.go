package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
)

// lockAuthority precedes every group, account, MFA and session row lock in an
// authority mutation. A schema-wide boundary also protects root grants and
// mutable role definitions. Login, verification and session reads do not use it.
func (s *Engine) lockAuthority(ctx context.Context, q db.DBTX) error {
	return db.New(q).AdvisoryXactLock(ctx, "authkit.authority."+s.dbSchema())
}

// Authority reads after a queued lock must use a new statement snapshot even
// when a host configures its pool with a stronger default isolation level.
func (s *Engine) beginAuthorityTransaction(ctx context.Context) (pgx.Tx, error) {
	return s.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

// withAuthorityMutation runs apply, a's change, in one authority transaction.
// The zero actor is AuthKit itself.
func (s *Engine) withAuthorityMutation(ctx context.Context, a iam.Actor, apply func(*permissionGroupStore) error) error {
	return s.withAuthorityMutationIn(ctx, a, nil, apply)
}

// withAuthorityMutationIn is withAuthorityMutation inside host, the host's own
// transaction, when host is set: a savepoint in it takes the authority lock
// (held until the host commits or rolls back), applies the change, sweeps
// credentials and records events, so all of it commits or rolls back with the
// host's own writes. A refused change rolls back to the savepoint and leaves
// host usable.
func (s *Engine) withAuthorityMutationIn(ctx context.Context, a iam.Actor, host pgx.Tx, apply func(*permissionGroupStore) error) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	var tx pgx.Tx
	var err error
	if host == nil {
		tx, err = s.beginAuthorityTransaction(ctx)
	} else {
		tx, err = s.joinHostTransaction(ctx, host)
	}
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	st := s.groupStoreFor(tx)
	st.actor = a
	if err := s.lockAuthority(ctx, st.q); err != nil {
		return err
	}
	if err := apply(st); err != nil {
		return err
	}
	if err := s.revokeUncoveredCredentials(ctx, st, st.touched...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// joinHostTransaction opens a savepoint in host. host must be a READ
// COMMITTED transaction on AuthKit's database: authority reads after the lock
// need a fresh snapshot per statement. The savepoint resolves AuthKit's
// tables through AuthKit's search_path, as the engine's own pool does, and
// gives the host its own back when it is released.
func (s *Engine) joinHostTransaction(ctx context.Context, host pgx.Tx) (pgx.Tx, error) {
	sp, err := host.Begin(ctx)
	if err != nil {
		return nil, err
	}
	q := db.New(sp)
	settings, err := q.TransactionSettings(ctx)
	if err == nil && settings.Isolation != "read committed" {
		err = fmt.Errorf("authkit: InTx needs a READ COMMITTED transaction, not %s", strings.ToUpper(settings.Isolation))
	}
	if err == nil {
		err = q.SetSearchPath(ctx, db.SetSearchPathParams{SearchPath: pgx.Identifier{s.dbSchema()}.Sanitize() + ", public", IsLocal: true})
	}
	if err != nil {
		_ = sp.Rollback(ctx)
		return nil, err
	}
	return hostSavepoint{Tx: sp, hostSearchPath: settings.SearchPath}, nil
}

// hostSavepoint is a savepoint in the host's transaction that restores the
// host's search_path when released.
type hostSavepoint struct {
	pgx.Tx
	hostSearchPath string
}

func (h hostSavepoint) Commit(ctx context.Context) error {
	if err := db.New(h.Tx).SetSearchPath(ctx, db.SetSearchPathParams{SearchPath: h.hostSearchPath, IsLocal: true}); err != nil {
		return err
	}
	return h.Tx.Commit(ctx)
}

// revokeUncoveredCredentials revokes live invite links, account invitations and
// API keys, and deletes the roles of group-registered applications, whose
// issuer could no longer issue them, after grants in the touched groups
// changed (root grants apply in every group, so a root touch sweeps the whole
// site). A credential never outlives the authority that issued it; otherwise a
// demoted creator could redeem their own link, or keep using their own key or
// application, to regain the role. System-issued credentials (no creator)
// are swept only for MFA: no key or application holds a role that needs it.
// It sweeps what this app issued, under its own catalog, and has every other
// account issuer sweep what it issued (enqueuePeerCredentialSweeps).
func (s *Engine) revokeUncoveredCredentials(ctx context.Context, st *permissionGroupStore, touched ...authorityTouch) error {
	seen := map[authorityTouch]bool{}
	var unique []authorityTouch
	var creds []sweptCredential
	for _, t := range touched {
		if seen[t] {
			continue
		}
		seen[t] = true
		unique = append(unique, t)
		rows, err := db.New(st.q).AuthorityUncoveredCredentials(ctx, db.AuthorityUncoveredCredentialsParams{GroupID: t.groupID, UserID: t.userID, Issuer: s.cfg.Token.Issuer})
		if err != nil {
			return err
		}
		for _, r := range rows {
			persona := ident.Persona(r.Persona)
			creds = append(creds, sweptCredential{
				table: r.Kind, id: r.ID, creator: r.Creator, needsCreator: r.NeedsCreator,
				group: groupTarget{ID: r.GroupID, Persona: persona}, role: ident.RoleText(r.Role),
			})
		}
	}
	revoked := map[string]bool{}
	for _, c := range creds {
		key := c.table + " " + c.group.ID + " " + c.id
		if revoked[key] {
			continue
		}
		stands, err := s.credentialStands(ctx, st, c)
		if err != nil || stands {
			if err != nil {
				return err
			}
			continue
		}
		if err := s.retireCredential(ctx, st, c); err != nil {
			return err
		}
		revoked[key] = true
	}
	if st.reconcile {
		return nil
	}
	return s.enqueuePeerCredentialSweeps(ctx, st.q, unique)
}

// sweptCredential is one credential the sweep re-checks. For an application
// role, id is the application and group the group of the role.
type sweptCredential struct {
	table, id, creator string
	group              groupTarget
	role               iam.Role
	needsCreator       bool // a group registration: no registrar confers nothing
}

// credentialStands is rule CRED for c: its creator still issues it, and a key
// or application role never needs MFA.
func (s *Engine) credentialStands(ctx context.Context, st *permissionGroupStore, c sweptCredential) (bool, error) {
	machine := c.table == "api_keys" || c.table == "group_remote_application_roles"
	if machine && s.TwoFactorEnabled() {
		if s.roleRequiresMFA(c.group.Persona, c.role) {
			return false, nil
		}
	}
	if c.creator == "" {
		return !c.needsCreator, nil
	}
	capability := ident.MembersManage(c.group.Persona)
	switch {
	case machine:
		capability = ident.CredentialsManage(c.group.Persona)
	case c.role.IsZero():
		capability = ident.RootUsersInvite
	}
	err := s.creatorCovers(ctx, st, c.creator, c.group, capability, c.role)
	if errors.Is(err, iam.ErrInsufficientAuthority) || errors.Is(err, iam.ErrRoleAssignmentEscalation) || errors.Is(err, iam.ErrRoleNotAssignable) {
		return false, nil
	}
	return err == nil, err
}

// retireCredential revokes c, or deletes an application's role. A change
// that strips the owner role of an application still counting as an owner
// (its live registrar lost cover) is refused like any other last-owner
// removal; a role that already conferred nothing (it needs MFA, or its
// registrar is gone) is no loss. A reconciling sweep never refuses: it retires
// and logs a group it leaves without a usable owner.
func (s *Engine) retireCredential(ctx context.Context, st *permissionGroupStore, c sweptCredential) error {
	if st.reconcile {
		slog.InfoContext(ctx, "authkit: credential sweep retired a credential", "kind", c.table, "id", c.id, "group_id", c.group.ID, "role", c.role)
	}
	if c.table == "group_remote_application_roles" {
		app := iam.RemoteApplicationSubject(c.id)
		if c.role.IsOwner() && !st.reconcile {
			if err := s.refuseOwnerLoss(ctx, st, c.group.ID, app); err != nil {
				return err
			}
		}
		if err := st.UnassignSubject(ctx, c.group.ID, app); err != nil {
			return err
		}
		if c.role.IsOwner() && st.reconcile {
			err := s.requireRemainingOwner(ctx, st, c.group.ID, iam.Subject{})
			if errors.Is(err, iam.ErrLastOwner) {
				slog.WarnContext(ctx, "authkit: the credential sweep left a group without a usable owner; assign one (ListGroups with GroupQuery.Ownerless lists them)", "group_id", c.group.ID, "remote_application_id", c.id)
				return nil
			}
			return err
		}
		return nil
	}
	q := db.New(st.q)
	switch c.table {
	case "api_keys":
		return q.APIKeyRetire(ctx, c.id)
	case "group_invite_links":
		return q.InviteLinkRetire(ctx, c.id)
	case "account_registration_invites":
		return q.AccountInviteRetire(ctx, c.id)
	}
	return fmt.Errorf("authkit: unknown credential kind %q", c.table)
}

// creatorCovers is rule CRED: the creator is still a live account (not
// banned or deleted), holds capability and covers role. A plain
// registration invite carries no role, so it needs capability only.
func (s *Engine) creatorCovers(ctx context.Context, st *permissionGroupStore, creator string, g groupTarget, capability iam.Perm, role iam.Role) error {
	if role.IsZero() {
		auth, err := s.actorAuthority(ctx, st, iam.UserActor(creator), g)
		if err != nil {
			return err
		}
		return auth.requireCap(capability)
	}
	return s.requireRoleGrant(ctx, st, iam.UserActor(creator), g, capability, role)
}

// revokeCredentialsOf re-checks every live API key, invite link and
// registration invite userID issued, in every group, and revokes those it no
// longer covers. Account lifecycle paths (ban, soft delete, reserve, and purge
// before the row goes) call it inside their authority transaction; after any
// of them the user covers nothing.
func (s *Engine) revokeCredentialsOf(ctx context.Context, st *permissionGroupStore, userID string) error {
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return err
	}
	return s.revokeUncoveredCredentials(ctx, st, authorityTouch{groupID: rootID, userID: userID})
}

// directRole is the subject's role in the group, the zero Role for none.
func (st *permissionGroupStore) directRole(ctx context.Context, g groupTarget, subject iam.Subject) (iam.Role, error) {
	q := db.New(st.q)
	var role string
	var err error
	switch subject.Kind {
	case iam.SubjectKindUser:
		role, err = q.GroupUserRoleName(ctx, db.GroupUserRoleNameParams{GroupID: g.ID, UserID: subject.ID})
	case iam.SubjectKindRemoteApplication:
		role, err = q.GroupApplicationRoleName(ctx, db.GroupApplicationRoleNameParams{GroupID: g.ID, ApplicationID: subject.ID})
	default:
		return iam.Role{}, invalidSubjectKind(subject.Kind)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Role{}, nil
	}
	return ident.RoleText(role), err
}

// userLive is the session check (#412), in one query: whether userID is
// usable, and whether the sign-in r names, when it names one, is still an
// active refresh session or device key of theirs. Logout, revoke-all, a
// password change, a ban and deletion all revoke sign-ins, so signedIn covers
// them; usable also covers sessions outside the configured account issuers.
func userLive(ctx context.Context, q db.DBTX, userID string, r iam.SessionRef) (usable, signedIn bool, err error) {
	switch {
	case !isUUID(userID):
		return false, true, nil // no such account: the account check refuses
	case r.SessionID != "" && !isUUID(r.SessionID), r.DeviceKeyID != "" && !isUUID(r.DeviceKeyID):
		return true, false, nil
	}
	live, err := db.New(q).UserSessionLive(ctx, db.UserSessionLiveParams{UserID: userID, SessionID: r.SessionID, DeviceKeyID: r.DeviceKeyID})
	return live.Usable, live.SignedIn, err
}

func subjectUsable(ctx context.Context, q db.DBTX, subject iam.Subject) (bool, error) {
	switch subject.Kind {
	case iam.SubjectKindUser:
		return db.New(q).UserUsable(ctx, subject.ID)
	case iam.SubjectKindRemoteApplication:
		return db.New(q).RemoteApplicationUsable(ctx, subject.ID)
	}
	return false, fmt.Errorf("invalid subject kind %q", subject.Kind)
}

// refuseOwnerLoss checks a specific departing assignment, excluding its subject
// from the remaining live owners. Removing a principal that does not count as
// an owner (unusable, or an application where owners need MFA) creates no
// ownership loss; empty bootstrap groups also remain possible.
func (s *Engine) refuseOwnerLoss(ctx context.Context, st *permissionGroupStore, gid string, subject iam.Subject) error {
	role, err := st.directRole(ctx, groupTarget{ID: gid}, subject)
	if err != nil || !role.IsOwner() {
		return err
	}
	live, err := subjectUsable(ctx, st.q, subject)
	if err == nil && live && subject.Kind == iam.SubjectKindRemoteApplication {
		var app db.AuthorityApplicationOwnsGroupRow
		app, err = db.New(st.q).AuthorityApplicationOwnsGroup(ctx, db.AuthorityApplicationOwnsGroupParams{GroupID: gid, ApplicationID: subject.ID})
		live = app.Controls && !s.ownersNeedMFA(ident.Persona(app.Persona))
	}
	if err != nil || !live {
		return err
	}
	return s.requireRemainingOwner(ctx, st, gid, subject)
}

// ownersNeedMFA reports whether only MFA-enrolled users count as owners of a
// persona's groups; applications then never do.
func (s *Engine) ownersNeedMFA(persona iam.Persona) bool {
	owner, _ := s.groupSchemaOrDefault().Role(persona, persona.OwnerRole())
	return s.TwoFactorEnabled() && (s.requireMFAEnrollment() || owner.RequiresMFA)
}

func (s *Engine) requireRemainingOwner(ctx context.Context, st *permissionGroupStore, gid string, excluding iam.Subject) error {
	q := db.New(st.q)
	g, err := q.AuthorityGroupState(ctx, gid)
	if err != nil {
		return err
	}
	if g.DeletedAt != nil {
		return nil
	}
	remains, err := q.GroupHasOtherUsableOwner(ctx, db.GroupHasOtherUsableOwnerParams{
		GroupID: gid, ExcludingKind: string(excluding.Kind), ExcludingID: nullable(excluding.ID), NeedsMfa: s.ownersNeedMFA(ident.Persona(g.Persona)),
	})
	if err != nil {
		return err
	}
	if !remains {
		return iam.ErrLastOwner
	}
	return nil
}

func (s *Engine) refuseSubjectOwnerLoss(ctx context.Context, st *permissionGroupStore, subject iam.Subject) error {
	var groups []string
	var err error
	switch subject.Kind {
	case iam.SubjectKindUser:
		groups, err = db.New(st.q).GroupsOwnedByUser(ctx, subject.ID)
	case iam.SubjectKindRemoteApplication:
		groups, err = db.New(st.q).GroupsOwnedByApplication(ctx, subject.ID)
	default:
		return invalidSubjectKind(subject.Kind)
	}
	if err != nil {
		return err
	}
	for _, gid := range groups {
		if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
			return err
		}
	}
	return nil
}

// An invitation is a bounded bearer grant, not the inviter's current authority.
// Redemption can retain or increase its recipient's role, never strip grants.
func (s *Engine) assignInvitedRole(ctx context.Context, st *permissionGroupStore, gid string, persona iam.Persona, userID string, role iam.Role) error {
	subject := iam.UserSubject(userID)
	g := groupTarget{ID: gid, Persona: persona}
	old, err := st.directRole(ctx, g, subject)
	if err != nil {
		return err
	}
	if !old.IsZero() && old != role {
		oldGrants, err := s.roleGrants(g.Persona, old)
		if err != nil {
			return err
		}
		offered, err := s.roleGrants(g.Persona, role)
		if err != nil {
			return err
		}
		if !grantsCoverAll(offered, oldGrants) {
			return iam.ErrRoleAssignmentEscalation
		}
		if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
			return err
		}
	}
	if err := s.requireDefinedGroupRole(persona, role); err != nil {
		return err
	}
	if err := s.requireMFAForRoleAssignment(ctx, st.q, gid, persona, subject, role); err != nil {
		return err
	}
	return st.AssignRole(ctx, gid, subject, role)
}

// A group deletion can also delete applications owning other groups. Check
// the surviving groups after all cascades, so departing apps cannot count one
// another as replacements. Caller already holds the authority transaction lock.
func outsideApplicationOwnerGroups(ctx context.Context, st *permissionGroupStore, gid string) ([]string, error) {
	return db.New(st.q).AuthorityOutsideApplicationOwnerGroups(ctx, gid)
}

func (s *Engine) deleteGroupTx(ctx context.Context, st *permissionGroupStore, gid string) error {
	surviving, err := outsideApplicationOwnerGroups(ctx, st, gid)
	if err != nil {
		return err
	}
	if err := st.DeleteGroup(ctx, gid); err != nil {
		return err
	}
	for _, id := range surviving {
		if err := s.requireRemainingOwner(ctx, st, id, iam.Subject{}); err != nil {
			return err
		}
	}
	return nil
}
