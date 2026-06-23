package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrTwoFAEnrollmentRequired = errors.New("2fa_enrollment_required")

type Mandatory2FAPolicy struct {
	GroupType   string
	ResourceRef string
	Roles       []string
}

type Mandatory2FAStatus struct {
	Required       bool
	Satisfied      bool
	AllowedMethods []string
}

func validateMandatory2FAPolicies(schema *GroupSchema, policies []Mandatory2FAPolicy) error {
	for i, p := range policies {
		groupType := strings.TrimSpace(p.GroupType)
		if groupType == "" {
			return fmt.Errorf("mandatory 2FA policy %d: group type is required", i)
		}
		if _, ok := schema.Type(groupType); !ok {
			return fmt.Errorf("mandatory 2FA policy %d: unknown group type %q", i, groupType)
		}
		if len(p.Roles) == 0 {
			return fmt.Errorf("mandatory 2FA policy %d: at least one role is required", i)
		}
		for _, role := range p.Roles {
			role = strings.TrimSpace(role)
			if role == "" {
				return fmt.Errorf("mandatory 2FA policy %d: empty role", i)
			}
			if _, ok := schema.Role(groupType, role); !ok {
				return fmt.Errorf("mandatory 2FA policy %d: unknown %s role %q", i, groupType, role)
			}
		}
	}
	return nil
}

func (s *Service) Mandatory2FAStatus(ctx context.Context, userID string) (Mandatory2FAStatus, error) {
	required, err := s.UserRequiresMandatory2FA(ctx, userID)
	if err != nil {
		return Mandatory2FAStatus{}, err
	}
	status := Mandatory2FAStatus{
		Required:  required,
		Satisfied: !required,
	}
	if !required {
		return status, nil
	}
	status.AllowedMethods = []string{"email", "sms", "totp"}
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return status, nil
		}
		return Mandatory2FAStatus{}, err
	}
	status.Satisfied = settings != nil && settings.Enabled && len(settings.Factors) > 0
	return status, nil
}

func (s *Service) UserSatisfiesMandatory2FA(ctx context.Context, userID string) (bool, error) {
	status, err := s.Mandatory2FAStatus(ctx, userID)
	if err != nil {
		return false, err
	}
	return status.Satisfied, nil
}

func (s *Service) UserRequiresMandatory2FA(ctx context.Context, userID string) (bool, error) {
	if len(s.opts.Mandatory2FA) == 0 {
		return false, nil
	}
	groups, err := s.ListSubjectGroups(ctx, userID, SubjectKindUser)
	if err != nil {
		return false, err
	}
	for _, group := range groups {
		for _, policy := range s.opts.Mandatory2FA {
			if !sameGroup(policy, group) {
				continue
			}
			for _, role := range policy.Roles {
				if strings.EqualFold(strings.TrimSpace(role), group.Role) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func sameGroup(policy Mandatory2FAPolicy, group SubjectGroupMembership) bool {
	return strings.TrimSpace(policy.GroupType) == group.Persona &&
		strings.TrimSpace(policy.ResourceRef) == group.ResourceRef
}

func hasAuthMethod(methods []string, want string) bool {
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), want) {
			return true
		}
	}
	return false
}
