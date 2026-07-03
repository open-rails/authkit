package authcore

import (
	"context"
	"errors"
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
	return s.requireSessionMFAStateWith(authMethods, status, err)
}

// requireSessionMFAStateWith applies the session MFA gate using an ALREADY-COMPUTED
// MFAStatus (and its lookup error) instead of reading it here (#227), so a caller
// that already read MFA state — the refresh / login / 2FA-verify paths — does not
// recompute it. Behaviour matches requireSessionMFAState exactly: statusErr is only
// consulted once 2FA is enabled (when 2FA is globally Disabled the gate short-circuits
// and never looks at MFA state, so a lookup error there is intentionally ignored).
func (s *Service) requireSessionMFAStateWith(authMethods []string, status MFAStatus, statusErr error) error {
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
		return nil
	}
	if !status.Satisfied || !hasAuthMethod(authMethods, "mfa") {
		return ErrTwoFAEnrollmentRequired
	}
	return nil
}

func (s *Service) roleRequiresMFA(persona, role string) bool {
	def, ok := s.groupSchemaOrDefault().Role(strings.TrimSpace(persona), strings.TrimSpace(role))
	return ok && def.RequiresMFA
}

func (s *Service) requireMFAForRoleAssignment(ctx context.Context, q db.DBTX, persona, subjectID, subjectKind, role string) error {
	if strings.TrimSpace(subjectKind) != SubjectKindUser || !s.roleRequiresMFA(persona, role) {
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
	defer rows.Close()

	var removals []RemovedMFARoleAssignment
	for rows.Next() {
		var r RemovedMFARoleAssignment
		if err := rows.Scan(&r.PermissionGroupID, &r.Persona, &r.InstanceSlug, &r.Role); err != nil {
			return nil, err
		}
		if s.roleRequiresMFA(r.Persona, r.Role) {
			r.RemovedAt = time.Now().UTC()
			removals = append(removals, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
