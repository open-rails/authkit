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

type RemovedMFARoleAssignment struct {
	PermissionGroupID string
	Persona           string
	InstanceSlug      string
	Role              string
	RemovedAt         time.Time
}

type MFAStatus = authkit.MFAStatus

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
		// Global policy: when 2FA enrollment is mandatory, a user without usable
		// 2FA cannot establish or refresh a session — they must enroll first.
		if s.opts.RequireMFAEnrollment {
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
