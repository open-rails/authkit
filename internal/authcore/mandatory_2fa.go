package authcore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

var ErrTwoFAEnrollmentRequired = errors.New("2fa_enrollment_required")

type RemovedMFARoleAssignment struct {
	GroupID      string
	Persona      string
	ResourceSlug string
	Role         string
	RemovedAt    time.Time
}

type MFAStatus struct {
	Enabled        bool
	Satisfied      bool
	AllowedMethods []string
}

func (s *Service) MFAStatus(ctx context.Context, userID string) (MFAStatus, error) {
	settings, err := s.Get2FASettings(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAStatus{}, nil
	}
	if err != nil {
		return MFAStatus{}, err
	}
	return MFAStatus{
		Enabled:        settings.Enabled,
		Satisfied:      settings.Enabled && len(settings.Factors) > 0,
		AllowedMethods: []string{"email", "sms", "totp"},
	}, nil
}

func (s *Service) requireSessionMFAState(ctx context.Context, userID string, authMethods []string) error {
	status, err := s.MFAStatus(ctx, userID)
	if err != nil {
		return err
	}
	if !status.Enabled {
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
		`SELECT a.group_id::text, g.persona, COALESCE(g.resource_slug, ''), a.role
		   FROM profiles.group_role_assignments a
		   JOIN profiles.permission_groups g ON g.id = a.group_id
		  WHERE a.subject_id = $1::uuid
		    AND a.subject_kind = 'user'
		    AND a.deleted_at IS NULL
		    AND g.deleted_at IS NULL`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var removals []RemovedMFARoleAssignment
	for rows.Next() {
		var r RemovedMFARoleAssignment
		if err := rows.Scan(&r.GroupID, &r.Persona, &r.ResourceSlug, &r.Role); err != nil {
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
			`UPDATE profiles.group_role_assignments
			    SET deleted_at = now(), updated_at = now()
			  WHERE group_id = $1::uuid
			    AND subject_id = $2::uuid
			    AND subject_kind = 'user'
			    AND role = $3
			    AND deleted_at IS NULL`,
			r.GroupID, userID, r.Role); err != nil {
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
