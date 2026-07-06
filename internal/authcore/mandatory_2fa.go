package authcore

import (
	"context"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

var ErrTwoFAEnrollmentRequired = authkit.ErrTwoFAEnrollmentRequired

// TwoFAEnrollmentRequiredError wraps ErrTwoFAEnrollmentRequired with the userID
// of the gated account, so the refresh-token path can mint a usable enrollment
// token instead of stranding the user (#148, grounding note b — a 403 with no
// token at refresh is a lockout). errors.Is(err, ErrTwoFAEnrollmentRequired)
// still matches.
type TwoFAEnrollmentRequiredError struct{ UserID string }

func (e *TwoFAEnrollmentRequiredError) Error() string { return ErrTwoFAEnrollmentRequired.Error() }
func (e *TwoFAEnrollmentRequiredError) Unwrap() error { return ErrTwoFAEnrollmentRequired }

type RemovedMFARoleAssignment struct {
	PermissionGroupID string
	Persona           string
	InstanceSlug      string
	Role              string
	RemovedAt         time.Time
}

type MFAStatus = authkit.MFAStatus

// Two-factor policy vocabulary is defined in authkit (core-free) and re-exported
// here (#148).
type TwoFactorMode = authkit.TwoFactorMode

const (
	TwoFactorDisabled = authkit.TwoFactorDisabled
	TwoFactorOptional = authkit.TwoFactorOptional
	TwoFactorRequired = authkit.TwoFactorRequired
)

type TwoFactorMethod = authkit.TwoFactorMethod

const (
	TwoFactorEmail = authkit.TwoFactorEmail
	TwoFactorSMS   = authkit.TwoFactorSMS
	TwoFactorTOTP  = authkit.TwoFactorTOTP
)

func (s *Service) MFAStatus(ctx context.Context, userID string) (MFAStatus, error) {
	settings, err := s.Get2FASettings(ctx, userID)
	return s.MFAStatusWith(settings, err)
}

// MFAStatusWith derives MFAStatus from an ALREADY-loaded Get2FASettings result
// (and its lookup error) instead of re-reading 2FA settings here (#228), so a
// caller that already read them — e.g. GET /me, which threads one Get2FASettings
// through MFAStatus, the step-up methods, and the step-up 2FA options — does not
// recompute the read. Behaviour matches MFAStatus exactly: a "no 2FA row" lookup
// (pgx.ErrNoRows) is the empty/disabled status, any other error propagates.
func (s *Service) MFAStatusWith(settings *TwoFactorSettings, settingsErr error) (MFAStatus, error) {
	if errors.Is(settingsErr, pgx.ErrNoRows) {
		return MFAStatus{}, nil
	}
	if settingsErr != nil {
		return MFAStatus{}, settingsErr
	}
	return MFAStatus{
		Enabled:        settings.Enabled,
		Satisfied:      settings.Enabled && len(settings.Factors) > 0,
		AllowedMethods: s.TwoFactorAllowedMethods(),
	}, nil
}

func (s *Service) requireSessionMFAState(ctx context.Context, userID string, authMethods []string) error {
	// #148: when 2FA is Disabled, the whole flow is off — neither forced
	// enrollment nor an enrolled user's challenge applies. (Guards against
	// stranding a user who enrolled while Optional after the host flips to
	// Disabled.) Read MFAStatus only when 2FA is enabled, then apply the gate.
	if !s.TwoFactorEnabled() {
		return nil
	}
	status, err := s.MFAStatus(ctx, userID)
	return s.requireSessionMFAStateWith(ctx, userID, authMethods, status, err)
}

// requireSessionMFAStateWith applies the session MFA gate using an ALREADY-COMPUTED
// MFAStatus (and its lookup error) instead of reading it here (#227), so a caller
// that already read MFA state — the refresh / login / 2FA-verify paths — does not
// recompute it. Behaviour matches requireSessionMFAState exactly: statusErr is only
// consulted once 2FA is enabled (when 2FA is globally Disabled the gate short-circuits
// and never looks at MFA state, so a lookup error there is intentionally ignored).
func (s *Service) requireSessionMFAStateWith(ctx context.Context, userID string, authMethods []string, status MFAStatus, statusErr error) error {
	if !s.TwoFactorEnabled() {
		return nil
	}
	if statusErr != nil {
		return statusErr
	}
	if !status.Enabled {
		// Global policy: when 2FA enrollment is mandatory, a user without usable
		// 2FA cannot establish or refresh a session — they must enroll first.
		if s.requireMFAEnrollment() {
			return ErrTwoFAEnrollmentRequired
		}
		// #249 follow-up: Mode==Optional otherwise lets an unenrolled user
		// through — EXCEPT a user holding a role whose RoleDef.RequiresMFA is
		// true. That combination arises when a role was assigned while
		// Mode==Disabled (requireMFAForRoleAssignment short-circuits there so
		// bootstrap can't brick itself) and the host later re-enables 2FA,
		// leaving an MFA-required role holder with no enrollment and no gate
		// to catch it. Reached only here — not enrolled, and Mode isn't
		// already Required — so an enrolled user or a Required deployment
		// never pays for the extra query.
		holds, err := s.userHoldsMFARequiredRole(ctx, db.ForSchema(s.pg, s.dbSchema()), userID)
		if err != nil {
			// Fail closed: a role-lookup error denies session establishment,
			// it does not silently skip the check.
			return err
		}
		if holds {
			return ErrTwoFAEnrollmentRequired
		}
		return nil
	}
	if !status.Satisfied || !hasAuthMethod(authMethods, "mfa") {
		return ErrTwoFAEnrollmentRequired
	}
	return nil
}

// roleRequiresMFA reports whether role (in persona) requires MFA: a catalog
// role's declared RoleDef.RequiresMFA, or — for a non-catalog role (#247) — a
// per-group custom role's stored requires_mfa flag, looked up in gid. gid may
// be empty when the role is known to be a catalog role at the call site (the
// custom-role branch is then simply skipped, reporting false).
func (s *Service) roleRequiresMFA(ctx context.Context, q db.DBTX, gid, persona, role string) (bool, error) {
	persona = strings.TrimSpace(persona)
	role = strings.TrimSpace(role)
	if def, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return def.RequiresMFA, nil
	}
	gid = strings.TrimSpace(gid)
	if gid == "" || role == "" {
		return false, nil
	}
	_, requiresMFA, err := NewPermissionGroupStore(q).CustomRole(ctx, gid, role)
	return requiresMFA, err
}

// userHoldsMFARequiredRole reports whether userID currently holds at least one
// role, in any permission group, that requires MFA — a catalog role with
// RoleDef.RequiresMFA or a custom role with requires_mfa (#247). Used only by
// requireSessionMFAStateWith (login/refresh session establishment) — never
// per-request middleware — since it hits the database.
func (s *Service) userHoldsMFARequiredRole(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	rows, err := q.Query(ctx,
		`SELECT a.permission_group_id::text, g.persona, a.role
		   FROM profiles.group_user_roles a
		   JOIN profiles.permission_groups g ON g.id = a.permission_group_id
		  WHERE a.user_id = $1::uuid
		    AND a.deleted_at IS NULL`,
		userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	// Collect first: roleRequiresMFA may itself query q (custom roles), which
	// cannot run while rows is open on a single-connection DBTX.
	type assignment struct{ gid, persona, role string }
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

func (s *Service) requireMFAForRoleAssignment(ctx context.Context, q db.DBTX, gid, persona, subjectID, subjectKind, role string) error {
	// #148/root-owner-MFA: RequiresMFA is inert when the deployment has no usable
	// 2FA (Mode == Disabled) — a fresh deployment must still be able to seed/assign
	// its root owner. Mirrors requireSessionMFAState's gate.
	if !s.TwoFactorEnabled() {
		return nil
	}
	if strings.TrimSpace(subjectKind) != SubjectKindUser {
		return nil
	}
	needsMFA, err := s.roleRequiresMFA(ctx, q, gid, persona, role)
	if err != nil {
		return err
	}
	if !needsMFA {
		return nil
	}
	ok, err := userHasEnabledMFA(ctx, q, strings.TrimSpace(subjectID))
	if err != nil {
		return err
	}
	if !ok {
		return ErrTwoFAEnrollmentRequired
	}
	return nil
}

func userHasEnabledMFA(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	var enabled bool
	err := q.QueryRow(ctx,
		`SELECT enabled FROM profiles.mfa_settings WHERE user_id = $1::uuid`,
		userID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || !enabled {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var hasFactor bool
	if err := q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM profiles.mfa_factors WHERE user_id = $1::uuid)`,
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
func (s *Service) removeMFARequiredUserRoles(ctx context.Context, q db.DBTX, userID string) ([]RemovedMFARoleAssignment, error) {
	rows, err := q.Query(ctx,
		`SELECT a.permission_group_id::text, g.persona, COALESCE(g.instance_slug, ''), a.role
		   FROM profiles.group_user_roles a
		   JOIN profiles.permission_groups g ON g.id = a.permission_group_id
		  WHERE a.user_id = $1::uuid
		    AND a.deleted_at IS NULL`,
		userID)
	if err != nil {
		return nil, err
	}
	// Drain + close the cursor BEFORE issuing any further query on q: q may be a
	// single-connection pgx.Tx, which cannot interleave a new query with an
	// still-open result set from a prior one.
	var candidates []RemovedMFARoleAssignment
	for rows.Next() {
		var r RemovedMFARoleAssignment
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

	var removals []RemovedMFARoleAssignment
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
	// Never orphan a group: refuse the whole disable outright if it would strip
	// the owner role from a group's LAST owner, rather than silently keeping the
	// role (2FA stays on) or silently stripping it (group left ownerless). The
	// caller must add another owner before disabling their own 2FA.
	st := NewPermissionGroupStore(q)
	for _, r := range removals {
		if r.Role != OwnerRoleName {
			continue
		}
		n, err := st.OwnerCount(ctx, r.PermissionGroupID)
		if err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, fmt.Errorf("disable 2fa: sole owner of %s group: %w", r.Persona, ErrCannotRemoveLastAdminRole)
		}
	}

	for _, r := range removals {
		if _, err := q.Exec(ctx,
			`UPDATE profiles.group_user_roles
			    SET deleted_at = now(), updated_at = now()
			  WHERE permission_group_id = $1::uuid
			    AND user_id = $2::uuid
			    AND role = $3
			    AND deleted_at IS NULL`,
			r.PermissionGroupID, userID, r.Role); err != nil {
			return nil, err
		}
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
