package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

var errTwoFARequired = errmodel.E(errmodel.CodeTwoFARequired)

func (s *Engine) mfaStatus(ctx context.Context, userID string) (authflow.MFAStatus, error) {
	settings, err := s.Get2FASettings(ctx, userID)
	return s.mfaStatusWith(settings, err)
}

// mfaStatusWith derives MFAStatus from an ALREADY-loaded Get2FASettings result
// (and its lookup error) instead of re-reading 2FA settings here (#228), so a
// caller that already read them — e.g. GET /me, which threads one Get2FASettings
// through MFAStatus, the step-up methods, and the step-up 2FA options — does not
// recompute the read. Behaviour matches MFAStatus exactly: a "no 2FA row" lookup
// (pgx.ErrNoRows) is the empty/disabled status, any other error propagates.
func (s *Engine) mfaStatusWith(settings *authflow.TwoFactorSettings, settingsErr error) (authflow.MFAStatus, error) {
	if errors.Is(settingsErr, pgx.ErrNoRows) {
		return authflow.MFAStatus{}, nil
	}
	if settingsErr != nil {
		return authflow.MFAStatus{}, settingsErr
	}
	return authflow.MFAStatus{
		Enabled:        settings.Enabled,
		Satisfied:      settings.Enabled && len(settings.Factors) > 0,
		AllowedMethods: s.TwoFactorAllowedMethods(),
	}, nil
}

// requireSessionMFAStateWith applies the session MFA gate using an ALREADY-COMPUTED
// MFAStatus (and its lookup error) instead of reading it here (#227), so a caller
// that already read MFA state — the refresh / login / 2FA-verify paths — does not
// recompute it. Behaviour matches requireSessionMFAState exactly: statusErr is only
// consulted once 2FA is enabled (when 2FA is globally Disabled the gate short-circuits
// and never looks at MFA state, so a lookup error there is intentionally ignored).
func (s *Engine) requireSessionMFAStateWith(ctx context.Context, userID string, authMethods []string, status authflow.MFAStatus, statusErr error) error {
	return s.requireSessionMFAStateOn(ctx, s.pg, userID, authMethods, status, statusErr)
}

func (s *Engine) requireSessionMFAStateOn(ctx context.Context, q db.DBTX, userID string, authMethods []string, status authflow.MFAStatus, statusErr error) error {
	if !s.TwoFactorEnabled() {
		return nil
	}
	if statusErr != nil {
		return statusErr
	}
	// A locally verified user-verifying passkey already supplies MFA proof.
	if hasAuthMethod(authMethods, "swk") && hasAuthMethod(authMethods, "mfa") {
		return nil
	}
	if !status.Enabled {
		// Global policy: when 2FA enrollment is mandatory, a user without usable
		// 2FA cannot establish or refresh a session — they must enroll first.
		if s.requireMFAEnrollment() {
			return iam.ErrTwoFAEnrollmentRequired
		}
		// #249 follow-up: Mode==Optional otherwise lets an unenrolled user
		// through — EXCEPT a user holding a role whose Role.RequiresMFA is
		// true. That combination arises when a role was assigned while
		// Mode==Disabled (requireMFAForRoleAssignment short-circuits there so
		// bootstrap can't brick itself) and the host later re-enables 2FA,
		// leaving an MFA-required role holder with no enrollment and no gate
		// to catch it. Reached only here — not enrolled, and Mode isn't
		// already Required — so an enrolled user or a Required deployment
		// never pays for the extra query.
		holds, err := s.userHoldsMFARequiredRole(ctx, q, userID)
		if err != nil {
			// Fail closed: a role-lookup error denies session establishment,
			// it does not silently skip the check.
			return err
		}
		if holds {
			return iam.ErrTwoFAEnrollmentRequired
		}
		return nil
	}
	if !status.Satisfied {
		return iam.ErrTwoFAEnrollmentRequired
	}
	if !hasAuthMethod(authMethods, "mfa") {
		return errTwoFARequired
	}
	return nil
}

// roleRequiresMFA reports whether role (in persona) needs MFA: its permissions
// reach one the schema marks as needing MFA (Persona.RequireMFA). A custom
// role is looked up in gid; with gid empty only catalog roles are known.
func (s *Engine) roleRequiresMFA(ctx context.Context, q db.DBTX, gid string, persona iam.Persona, role iam.Role) (bool, error) {
	persona = iam.Persona(strings.TrimSpace(string(persona)))
	role = iam.Role(strings.TrimSpace(string(role)))
	sch := s.groupSchemaOrDefault()
	if def, ok := sch.Role(persona, role); ok {
		return def.RequiresMFA, nil
	}
	gid = strings.TrimSpace(gid)
	if gid == "" || role == "" {
		return false, nil
	}
	grants, _, err := newPermissionGroupStore(q).CustomRole(ctx, gid, role)
	return sch.RequiresMFA(grants), err
}

// userHoldsMFARequiredRole reports whether userID currently holds at least one
// role, in any permission group, whose permissions need MFA. Used only by
// requireSessionMFAStateWith (login/refresh session establishment) — never
// per-request middleware — since it hits the database.
func (s *Engine) userHoldsMFARequiredRole(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	rows, err := q.Query(ctx,
		`SELECT a.permission_group_id::text, g.persona, a.role
		   FROM group_user_roles a
		   JOIN permission_groups g ON g.id = a.permission_group_id
		  WHERE a.user_id = $1::uuid`,
		userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	// Collect first: roleRequiresMFA may itself query q (custom roles), which
	// cannot run while rows is open on a single-connection DBTX.
	type assignment struct {
		gid     string
		persona iam.Persona
		role    iam.Role
	}
	var assignments []assignment
	for rows.Next() {
		var a assignment
		if err := rows.Scan(&a.gid, &a.persona, &a.role); err != nil {
			return false, err
		}
		assignments = append(assignments, a)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, a := range assignments {
		requires, err := s.roleRequiresMFA(ctx, q, a.gid, a.persona, a.role)
		if err != nil {
			return false, err
		}
		if requires {
			return true, nil
		}
	}
	return false, nil
}

func (s *Engine) requireMFAForRoleAssignment(ctx context.Context, q db.DBTX, gid string, persona iam.Persona, subject iam.Subject, role iam.Role) error {
	// #148/root-owner-MFA: RequiresMFA is inert when the deployment has no usable
	// 2FA (Mode == Disabled) — a fresh deployment must still be able to seed/assign
	// its root owner. Mirrors requireSessionMFAState's gate.
	if !s.TwoFactorEnabled() {
		return nil
	}
	needsMFA, err := s.roleRequiresMFA(ctx, q, gid, persona, role)
	if err != nil || !needsMFA {
		return err
	}
	// An application can never enroll a second factor.
	if subject.Kind != iam.SubjectKindUser {
		return fmt.Errorf("role %q requires MFA, which an application cannot hold: %w", role, iam.ErrRoleNotAssignable)
	}
	ok, err := userHasEnabledMFA(ctx, q, strings.TrimSpace(subject.ID))
	if err != nil {
		return err
	}
	if !ok {
		return iam.ErrTwoFAEnrollmentRequired
	}
	return nil
}

func userHasEnabledMFA(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	var enabled bool
	err := q.QueryRow(ctx,
		`SELECT enabled FROM mfa_settings WHERE user_id = $1::uuid`,
		userID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || !enabled {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var hasFactor bool
	if err := q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = $1::uuid)`,
		userID).Scan(&hasFactor); err != nil {
		return false, err
	}
	return hasFactor, nil
}

// removeMFARequiredUserRoles strips a user's MFA-required role assignments when
// THEY disable their own 2FA. This is a user decision, not app-level
// enforcement — unlike requireMFAForRoleAssignment (which the host's TwoFactor
// Mode gates), this runs regardless of Mode: holding a role that requires MFA
// without MFA enrolled is inconsistent independent of whether the app is
// currently enforcing it, and application-mode toggles must never themselves
// mutate role/2FA state (only gate checks).
func (s *Engine) removeMFARequiredUserRoles(ctx context.Context, q db.DBTX, userID string) ([]authflow.RemovedMFARoleAssignment, error) {
	rows, err := q.Query(ctx,
		`SELECT a.permission_group_id::text, g.persona, COALESCE(g.instance_slug, ''), a.role
		   FROM group_user_roles a
		   JOIN permission_groups g ON g.id = a.permission_group_id
		  WHERE a.user_id = $1::uuid`,
		userID)
	if err != nil {
		return nil, err
	}
	// Drain + close the cursor BEFORE issuing any further query on q: q may be a
	// single-connection pgx.Tx, which cannot interleave a new query with an
	// still-open result set from a prior one.
	var candidates []authflow.RemovedMFARoleAssignment
	for rows.Next() {
		var r authflow.RemovedMFARoleAssignment
		if err := rows.Scan(&r.PermissionGroupID, &r.Persona, &r.InstanceSlug, &r.Role); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, r)
	}
	rerr := rows.Err()
	rows.Close()
	if rerr != nil {
		return nil, rerr
	}

	var removals []authflow.RemovedMFARoleAssignment
	for _, r := range candidates {
		needsMFA, err := s.roleRequiresMFA(ctx, q, r.PermissionGroupID, r.Persona, r.Role)
		if err != nil {
			return nil, err
		}
		if needsMFA {
			r.RemovedAt = time.Now().UTC()
			removals = append(removals, r)
		}
	}
	st := s.groupStoreFor(q)
	st.actor = iam.UserActor(userID)
	if s.TwoFactorEnabled() && s.requireMFAEnrollment() {
		if err := s.refuseSubjectOwnerLoss(ctx, st, iam.UserSubject(userID)); err != nil {
			return nil, err
		}
	}
	for _, r := range removals {
		if err := s.refuseOwnerLoss(ctx, st, r.PermissionGroupID, iam.UserSubject(userID)); err != nil {
			return nil, err
		}
	}

	for _, r := range removals {
		if err := st.UnassignRole(ctx, r.PermissionGroupID, iam.UserSubject(userID), r.Role); err != nil {
			return nil, err
		}
	}
	if err := s.revokeUncoveredCredentials(ctx, st, st.touched...); err != nil {
		return nil, err
	}
	return removals, nil
}

func hasAuthMethod(methods []string, want string) bool {
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), want) {
			return true
		}
	}
	return false
}
