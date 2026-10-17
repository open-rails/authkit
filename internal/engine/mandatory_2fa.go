package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
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
		AllowedMethods: s.TwoFactorMethods(),
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
	required, err := s.userRequiresMFA(ctx, q, userID)
	if err != nil {
		return err
	}
	if required {
		if s.pg == nil {
			if !status.Enabled || !status.Satisfied {
				return iam.ErrTwoFAEnrollmentRequired
			}
			if !policyMFAProof(authMethods) {
				return errTwoFARequired
			}
			return nil
		}
		enrolled, err := s.policyMFAEnrolled(ctx, q, userID)
		if err != nil {
			return err
		}
		if !enrolled {
			return iam.ErrTwoFAEnrollmentRequired
		}
		if !policyMFAProof(authMethods) {
			return errTwoFARequired
		}
		return nil
	}
	if !status.Enabled {
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

// A requirement is effective policy, not a delayed role mutation. Reading it
// live makes both existing sessions and subsequent logins see policy changes.
func (s *Engine) userRequiresMFA(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	if !s.TwoFactorEnabled() {
		return false, nil
	}
	if s.requireMFAEnrollment() {
		return true, nil
	}
	if s.pg == nil {
		return false, nil
	}
	required, err := db.New(q).UserMFARequirement(ctx, userID)
	if err != nil || required {
		return required, err
	}
	return s.userHoldsMFARequiredRole(ctx, q, userID)
}

// Trusted Go callers still cannot turn a pending human role into usable
// authority. Request authenticators additionally require a proven MFA session.
func (s *Engine) requireUserMFAEnrollment(ctx context.Context, q db.DBTX, userID string, resolvedGrants ...[]string) error {
	required, err := s.userRequiresMFA(ctx, q, userID)
	if err != nil {
		return err
	}
	// Recheck the actual grants being returned: a concurrent role assignment
	// may have landed after the policy lookup above.
	if s.TwoFactorEnabled() {
		for _, grants := range resolvedGrants {
			required = required || s.groupSchemaOrDefault().RequiresMFA(grants)
		}
	}
	if !required {
		return nil
	}
	usable, err := s.policyMFAEnrolled(ctx, q, userID)
	if err != nil || usable {
		return err
	}
	return iam.ErrTwoFAEnrollmentRequired
}

// userHoldsMFARequiredRole reports whether userID currently holds at least one
// role, in any live permission group, whose permissions need MFA.
func (s *Engine) userHoldsMFARequiredRole(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	assignments, err := db.New(q).UserGroupRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, a := range assignments {
		if s.assignedRoleRequiresMFA(ident.Persona(a.Persona), ident.RoleText(a.Role), a.CustomPermissions) {
			return true, nil
		}
	}
	return false, nil
}

// assignedRoleRequiresMFA reports whether a held role, read with its custom
// definition, needs MFA.
func (s *Engine) assignedRoleRequiresMFA(persona iam.Persona, role iam.Role, custom []string) bool {
	r, ok := s.groupSchemaOrDefault().AssignedRole(persona, role, custom)
	return ok && r.RequiresMFA
}

func (s *Engine) requireMFAForRoleAssignment(ctx context.Context, q db.DBTX, gid string, persona iam.Persona, subject iam.Subject, role iam.Role) error {
	// #148/root-owner-MFA: RequiresMFA is inert when the deployment has no usable
	// 2FA (Mode == Disabled) — a fresh deployment must still be able to seed/assign
	// its root owner. Mirrors requireSessionMFAState's gate.
	if !s.TwoFactorEnabled() {
		return nil
	}
	needs, err := s.roleRequiresMFA(ctx, q, groupTarget{ID: gid, Persona: persona}, role)
	if err != nil || !needs {
		return err
	}
	// An application can never enroll a second factor.
	if subject.Kind != iam.SubjectKindUser {
		return fmt.Errorf("role %q requires MFA, which an application cannot hold: %w", role, iam.ErrRoleNotAssignable)
	}
	// Assign the human's role now. Authentication and live authorization
	// enforce enrollment before its permissions can be used.
	return nil
}

func hasAuthMethod(methods []string, want string) bool {
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), want) {
			return true
		}
	}
	return false
}

func strongFactorMethod(method string) bool { return method == "totp" || method == "sms" }

func policyMFAProof(methods []string) bool {
	if !hasAuthMethod(methods, "mfa") {
		return false
	}
	for _, method := range []string{"swk", "totp", "sms", "backup_code", "device_key"} {
		if hasAuthMethod(methods, method) {
			return true
		}
	}
	return false
}

// Enrolled and configured is distinct from deliverable right now. An SMS
// outage cannot turn an enrolled account into a password-only setup account.
func (s *Engine) policyMFAEnrolled(ctx context.Context, source db.DBTX, userID string) (bool, error) {
	factors, err := db.New(source).MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, factor := range factors {
		if strongFactorMethod(factor.Method) && s.twoFactorMethodConfigured(iam.TwoFactorMethod(factor.Method)) {
			return true, nil
		}
	}
	if !s.PasskeysEnabled() {
		return false, nil
	}
	return s.holdsAnyPasskey(ctx, source, userID)
}

func policyFactorSettings(settings *authflow.TwoFactorSettings) *authflow.TwoFactorSettings {
	if settings == nil {
		return nil
	}
	out := *settings
	out.Factors = nil
	for _, factor := range settings.Factors {
		if strongFactorMethod(factor.Method) {
			out.Factors = append(out.Factors, factor)
		}
	}
	out.Enabled = len(out.Factors) > 0
	return &out
}
