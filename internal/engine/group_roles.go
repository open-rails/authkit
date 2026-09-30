package engine

// Group role operations on the shared authority helper (authority.go). A user
// subject needs CAP(<persona>:members:manage), an application subject
// CAP(<persona>:credentials:manage); both need COVER of every role they grant
// or take away, so nobody hands out or strips authority above their own (only
// an owner can mint or remove an owner). The last usable owner and
// MFA-required roles are invariants that bind the system too.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/rbac"
)

// grantsCoverAll reports whether actorGrants cover every permission in targetGrants.
func grantsCoverAll(actorGrants, targetGrants []string) bool {
	for _, tp := range targetGrants {
		if !rbac.Covers(actorGrants, ident.Perm(tp)) {
			return false
		}
	}
	return true
}

// SetGroupRole makes subject hold role in ref, replacing the role it holds:
// CAP by subject kind, COVER(role), and when replacing, COVER(old) and the
// last-owner check. An application subject must be controlled by the group.
// Holding role already changes nothing.
func (s *Engine) SetGroupRole(ctx context.Context, a iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role, opts ...ops.Option) (iam.GroupMember, error) {
	tx, err := hostTx("SetGroupRole", opts)
	if err != nil {
		return iam.GroupMember{}, err
	}
	subject, err = groupSubject(a, subject)
	if err != nil {
		return iam.GroupMember{}, err
	}
	err = s.withGroupMutationIn(ctx, a, tx, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !s.validRoleForPersona(s.groupSchemaOrDefault(), g.Persona, role) {
			return fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
		}
		if err := s.requireDefinedGroupRole(g.Persona, role); err != nil {
			return err
		}
		auth, err := s.subjectCap(ctx, st, a, g, subject)
		if err != nil {
			return err
		}
		if err := s.requireAssignableSubject(ctx, st, g, subject); err != nil {
			return err
		}
		if err := s.requireRoleCover(ctx, st, auth, g, role); err != nil {
			return err
		}
		old, err := st.directRole(ctx, g, subject)
		if err != nil || old == role {
			return err
		}
		if !old.IsZero() {
			if err := s.requireRoleCover(ctx, st, auth, g, old); err != nil {
				return err
			}
			if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
				return err
			}
		}
		if err := s.requireMFAForRoleAssignment(ctx, st.q, g.ID, g.Persona, subject, role); err != nil {
			return err
		}
		if err := s.requireRegistrarCover(ctx, st, g, subject, role); err != nil {
			return err
		}
		return st.AssignRole(ctx, g.ID, subject, role)
	})
	if err != nil {
		return iam.GroupMember{}, err
	}
	return iam.GroupMember{Subject: subject, Role: role}, nil
}

// RemoveGroupMember strips subject's role in ref: CAP by subject kind, COVER
// of the role it holds, then the last-owner check. A non-member is a no-op, as
// is a subject holding another role than ops.IfRole names.
func (s *Engine) RemoveGroupMember(ctx context.Context, a iam.Actor, ref iam.GroupRef, subject iam.Subject, opts ...ops.Option) error {
	o, err := ops.Resolve("RemoveGroupMember", opts, ops.KindTx, ops.KindIfRole)
	if err != nil {
		return err
	}
	subject, err = groupSubject(a, subject)
	if err != nil {
		return err
	}
	return s.withGroupMutationIn(ctx, a, o.Tx, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !o.IfRole.IsZero() && o.IfRole.Persona() != g.Persona {
			return fmt.Errorf("role %q is not a role of a %q group: %w", o.IfRole, g.Persona, iam.ErrRoleNotAssignable)
		}
		auth, err := s.subjectCap(ctx, st, a, g, subject)
		if err != nil {
			return err
		}
		current, err := st.directRole(ctx, g, subject)
		if err != nil || current.IsZero() || !o.IfRole.IsZero() && current != o.IfRole {
			return err
		}
		if err := s.requireRoleCover(ctx, st, auth, g, current); err != nil {
			return err
		}
		if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
			return err
		}
		return st.UnassignRole(ctx, g.ID, subject, current)
	})
}

// groupSubject validates the actor and subject of a role change. Ids are
// compared as text downstream (self rules, the sweep's issuer filter): only
// the canonical form may travel (P4).
func groupSubject(a iam.Actor, subject iam.Subject) (iam.Subject, error) {
	if err := requireActor(a); err != nil {
		return subject, err
	}
	subject.ID = strings.TrimSpace(subject.ID)
	if err := validSubject(subject); err != nil {
		return subject, err
	}
	subject.ID, _ = canonicalUUID(subject.ID)
	return subject, nil
}

// requireRegistrarCover: a group-registered application acts with the
// authority of the user who supplied its keys (rule CRED), so it holds only a
// role its registrar could issue it. This binds the system too.
func (s *Engine) requireRegistrarCover(ctx context.Context, st *permissionGroupStore, g groupTarget, subject iam.Subject, role iam.Role) error {
	if subject.Kind != iam.SubjectKindRemoteApplication {
		return nil
	}
	app, err := db.New(st.q).RemoteApplicationByID(ctx, subject.ID)
	if err != nil {
		return err
	}
	stands, err := s.credentialStands(ctx, st, sweptCredential{table: "group_remote_application_roles", id: subject.ID, creator: deref(app.RegisteredBy), group: g, role: role, needsCreator: app.TrustRoot == "user"})
	if err != nil || stands {
		return err
	}
	return fmt.Errorf("the application's registrar cannot issue role %q: %w", role, iam.ErrRoleAssignmentEscalation)
}

// subjectCap resolves the actor's authority in g and checks the subject
// kind's capability.
func (s *Engine) subjectCap(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, subject iam.Subject) (authority, error) {
	auth, err := s.actorAuthority(ctx, st, a, g)
	if err != nil {
		return authority{}, err
	}
	capability := ident.MembersManage(g.Persona)
	if subject.Kind == iam.SubjectKindRemoteApplication {
		capability = ident.CredentialsManage(g.Persona)
	}
	return auth, auth.requireCap(capability)
}

func validSubject(subject iam.Subject) error {
	switch subject.Kind {
	case iam.SubjectKindUser:
		if !isUUID(subject.ID) {
			return iam.ErrUserNotFound
		}
	case iam.SubjectKindRemoteApplication:
		if !isUUID(subject.ID) {
			return iam.ErrRemoteApplicationNotFound
		}
	default:
		return invalidSubjectKind(subject.Kind)
	}
	return nil
}

// requireAssignableSubject: a user must exist; an application must be
// controlled by g, since roles elsewhere never take effect.
func (s *Engine) requireAssignableSubject(ctx context.Context, st *permissionGroupStore, g groupTarget, subject iam.Subject) error {
	q := db.New(st.q)
	if subject.Kind == iam.SubjectKindUser {
		exists, err := q.UserExists(ctx, subject.ID)
		if err != nil {
			return err
		}
		if !exists {
			return iam.ErrUserNotFound
		}
		return nil
	}
	app, err := q.RemoteApplicationByID(ctx, subject.ID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && app.PermissionGroupID != g.ID {
		return iam.ErrRemoteApplicationNotFound
	}
	return err
}

// GroupRoles returns the direct role of each subject that holds one in the
// group, for at most iam.MaxBatch subjects. Roles no longer defined (catalog
// or custom) confer nothing and are omitted.
func (s *Engine) GroupRoles(ctx context.Context, ref iam.GroupRef, subjects []iam.Subject) (map[iam.Subject]iam.Role, error) {
	out := map[iam.Subject]iam.Role{}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if len(subjects) > iam.MaxBatch {
		return nil, fmt.Errorf("batch has %d subjects; at most %d", len(subjects), iam.MaxBatch)
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return nil, err
	}
	var users, apps []string
	for _, subject := range subjects {
		if validSubject(subject) != nil {
			continue
		}
		if subject.Kind == iam.SubjectKindUser {
			users = append(users, subject.ID)
		} else {
			apps = append(apps, subject.ID)
		}
	}
	if len(users)+len(apps) == 0 {
		return out, nil
	}
	rows, err := db.New(st.q).GroupRolesForSubjects(ctx, db.GroupRolesForSubjectsParams{GroupID: g.ID, UserIds: users, ApplicationIds: apps})
	if err != nil {
		return nil, err
	}
	held := map[iam.Subject]iam.Role{}
	for _, r := range rows {
		held[iam.Subject{Kind: iam.SubjectKind(r.Kind), ID: r.SubjectID}] = ident.RoleText(r.Role)
	}
	sch := s.groupSchemaOrDefault()
	for _, subject := range subjects {
		subject.ID = strings.TrimSpace(subject.ID)
		role, ok := held[iam.Subject{Kind: subject.Kind, ID: strings.ToLower(subject.ID)}]
		if !ok {
			continue
		}
		if _, catalog := sch.Role(g.Persona, role); catalog {
			out[subject] = role
		}
	}
	return out, nil
}
