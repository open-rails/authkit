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
)

// grantsCoverAll reports whether actorGrants cover every permission in targetGrants.
func grantsCoverAll(actorGrants, targetGrants []string) bool {
	for _, tp := range targetGrants {
		if !iam.AnyGrantCovers(actorGrants, iam.Perm(tp)) {
			return false
		}
	}
	return true
}

// AssignGroupRoles assigns role to each subject, replacing a different role
// it holds. Per item: CAP by subject kind, COVER(role), and when replacing,
// COVER(old) and the last-owner check. An application subject must be
// controlled by the group. An already-held role is a no-op.
func (s *Engine) AssignGroupRoles(ctx context.Context, a iam.Actor, ref iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error) {
	role = iam.Role(strings.TrimSpace(string(role)))
	prepare := func(st *permissionGroupStore, g groupTarget) error {
		if !s.validRoleForPersona(s.groupSchemaOrDefault(), g.Persona, role) {
			return fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
		}
		return s.requireDefinedGroupRole(ctx, st, g.ID, g.Persona, role)
	}
	return s.groupRoleBatch(ctx, a, ref, subjects, prepare, func(st *permissionGroupStore, g groupTarget, subject iam.Subject) error {
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
		old, err := st.directRole(ctx, g.ID, subject)
		if err != nil || old == role {
			return err
		}
		if old != "" {
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
}

// requireRegistrarCover: a group-registered application acts with the
// authority of the user who supplied its keys (rule CRED), so it holds only a
// role its registrar could issue it. This binds the system too.
func (s *Engine) requireRegistrarCover(ctx context.Context, st *permissionGroupStore, g groupTarget, subject iam.Subject, role iam.Role) error {
	if subject.Kind != iam.SubjectKindRemoteApplication {
		return nil
	}
	var userRooted bool
	var registrar string
	if err := st.q.QueryRow(ctx, `SELECT trust_root='user', COALESCE(registered_by::text,'') FROM remote_applications WHERE id=$1::uuid`, subject.ID).Scan(&userRooted, &registrar); err != nil {
		return err
	}
	stands, err := s.credentialStands(ctx, st, sweptCredential{table: "group_remote_application_roles", id: subject.ID, creator: registrar, group: g, role: role, needsCreator: userRooted})
	if err != nil || stands {
		return err
	}
	return fmt.Errorf("the application's registrar cannot issue role %q: %w", role, iam.ErrRoleAssignmentEscalation)
}

// UnassignGroupRoles revokes role from each subject that holds it: CAP by
// subject kind and COVER(role), then the last-owner check. A subject not
// holding role is a no-op.
func (s *Engine) UnassignGroupRoles(ctx context.Context, a iam.Actor, ref iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error) {
	role = iam.Role(strings.TrimSpace(string(role)))
	prepare := func(*permissionGroupStore, groupTarget) error {
		if role == "" {
			return iam.ErrRoleNotAssignable
		}
		return nil
	}
	return s.groupRoleBatch(ctx, a, ref, subjects, prepare, func(st *permissionGroupStore, g groupTarget, subject iam.Subject) error {
		auth, err := s.subjectCap(ctx, st, a, g, subject)
		if err != nil {
			return err
		}
		if err := s.requireRoleCover(ctx, st, auth, g, role); err != nil {
			return err
		}
		current, err := st.directRole(ctx, g.ID, subject)
		if err != nil || current != role {
			return err
		}
		if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
			return err
		}
		return st.UnassignRole(ctx, g.ID, subject, role)
	})
}

// RemoveGroupMembers strips each subject's role: CAP by subject kind and COVER
// of the role it holds, then the last-owner check. A non-member is a no-op.
func (s *Engine) RemoveGroupMembers(ctx context.Context, a iam.Actor, ref iam.GroupRef, subjects []iam.Subject) ([]iam.OpResult, error) {
	return s.groupRoleBatch(ctx, a, ref, subjects, nil, func(st *permissionGroupStore, g groupTarget, subject iam.Subject) error {
		auth, err := s.subjectCap(ctx, st, a, g, subject)
		if err != nil {
			return err
		}
		current, err := st.directRole(ctx, g.ID, subject)
		if err != nil || current == "" {
			return err
		}
		if err := s.requireRoleCover(ctx, st, auth, g, current); err != nil {
			return err
		}
		if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
			return err
		}
		return st.UnassignSubject(ctx, g.ID, subject)
	})
}

// groupRoleBatch runs item once per subject in one authority transaction, each
// under a savepoint so a failed item rolls back alone. The zero actor, an
// unknown group, a failing prepare, a dead actor or an oversized batch fail
// the whole call.
func (s *Engine) groupRoleBatch(ctx context.Context, a iam.Actor, ref iam.GroupRef, subjects []iam.Subject, prepare func(*permissionGroupStore, groupTarget) error, item func(*permissionGroupStore, groupTarget, iam.Subject) error) ([]iam.OpResult, error) {
	if err := requireActor(a); err != nil {
		return nil, err
	}
	if len(subjects) > iam.MaxBatch {
		return nil, fmt.Errorf("batch has %d subjects; at most %d", len(subjects), iam.MaxBatch)
	}
	out := make([]iam.OpResult, len(subjects))
	if len(subjects) == 0 {
		return out, nil
	}
	err := s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if prepare != nil {
			if err := prepare(st, g); err != nil {
				return err
			}
		}
		if _, err := s.actorAuthority(ctx, st, a, g); err != nil {
			return err
		}
		for i, subject := range subjects {
			subject.ID = strings.TrimSpace(subject.ID)
			out[i].ID = subject.ID
			out[i].Err = st.savepoint(ctx, func() error {
				if err := validSubject(subject); err != nil {
					return err
				}
				// Ids are compared as text downstream (self rules, the sweep's
				// issuer filter): only the canonical form may travel (P4).
				subject.ID, _ = canonicalUUID(subject.ID)
				return item(st, g, subject)
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// subjectCap resolves the actor's authority in g (re-read per item, so an
// earlier item's change applies) and checks the subject kind's capability.
func (s *Engine) subjectCap(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, subject iam.Subject) (authority, error) {
	auth, err := s.actorAuthority(ctx, st, a, g)
	if err != nil {
		return authority{}, err
	}
	capability := iam.PermMembersManage(g.Persona)
	if subject.Kind == iam.SubjectKindRemoteApplication {
		capability = iam.PermCredentialsManage(g.Persona)
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
		return fmt.Errorf("invalid group subject kind %q", subject.Kind)
	}
	return nil
}

// requireAssignableSubject: a user must exist; an application must be
// controlled by g, since roles elsewhere never take effect.
func (s *Engine) requireAssignableSubject(ctx context.Context, st *permissionGroupStore, g groupTarget, subject iam.Subject) error {
	if subject.Kind == iam.SubjectKindUser {
		var exists bool
		if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid)`, subject.ID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return iam.ErrUserNotFound
		}
		return nil
	}
	var control string
	err := st.q.QueryRow(ctx, `SELECT permission_group_id::text FROM remote_applications WHERE id=$1::uuid`, subject.ID).Scan(&control)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && control != g.ID {
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
	rows, err := st.q.Query(ctx, `SELECT 'user', user_id::text, role FROM group_user_roles WHERE permission_group_id=$1::uuid AND user_id=ANY($2::uuid[])
 UNION ALL SELECT 'remote_application', remote_application_id::text, role FROM group_remote_application_roles WHERE permission_group_id=$1::uuid AND remote_application_id=ANY($3::uuid[])`, g.ID, users, apps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	held := map[iam.Subject]iam.Role{}
	for rows.Next() {
		var subject iam.Subject
		var role iam.Role
		if err := rows.Scan(&subject.Kind, &subject.ID, &role); err != nil {
			return nil, err
		}
		held[subject] = role
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	sch := s.groupSchemaOrDefault()
	resolver, err := st.CustomRolesFor(ctx, []string{g.ID})
	if err != nil {
		return nil, err
	}
	td, _ := sch.Persona(g.Persona)
	for _, subject := range subjects {
		subject.ID = strings.TrimSpace(subject.ID)
		role, ok := held[iam.Subject{Kind: subject.Kind, ID: strings.ToLower(subject.ID)}]
		if !ok {
			continue
		}
		if _, catalog := sch.Role(g.Persona, role); catalog {
			out[subject] = role
		} else if _, custom := resolver(g.ID, role); custom && td.CustomRoles {
			out[subject] = role
		}
	}
	return out, nil
}
