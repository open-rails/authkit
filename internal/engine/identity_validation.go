package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/naming"
	"github.com/open-rails/authkit/internal/password"
)

// ValidateUsername applies the configured username rule.
func (s *Engine) ValidateUsername(username string) error {
	return naming.Validate(s.cfg.Username, username)
}

// ValidatePassword applies the configured password policy. identifiers are
// the account's username and email address when known. Length failures carry
// min_length/max_length; requirement failures carry the missing classes.
func (s *Engine) ValidatePassword(value string, identifiers ...string) error {
	return validatePassword(*s.cfg.Password, value, identifiers...)
}

func validatePassword(p config.PasswordPolicy, value string, identifiers ...string) error {
	ids := make([]string, 0, len(identifiers))
	for _, id := range identifiers {
		if local := password.EmailLocalPart(id); local != "" {
			id = local
		}
		ids = append(ids, id)
	}
	err := password.Validate(p, value, ids...)
	var unmet *password.RequirementsError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &unmet):
		return errmodel.E(errmodel.CodePasswordRequirementsUnmet, errmodel.WithDetails(errmodel.PasswordRequirements{Missing: unmet.Missing}))
	case errors.Is(err, password.ErrTooCommon):
		return errmodel.E(errmodel.CodePasswordTooCommon)
	case errors.Is(err, password.ErrContainsIdentifier):
		return errmodel.E(errmodel.CodePasswordContainsIdentifier)
	}
	code := errmodel.CodePasswordTooShort
	if errors.Is(err, password.ErrTooLong) {
		code = errmodel.CodePasswordTooLong
	}
	return errmodel.E(code, errmodel.WithDetails(errmodel.LengthBounds{MinLength: p.MinLength, MaxLength: p.MaxLength}))
}

// passwordIdentifiers loads the account identifiers a new password may not contain.
func (s *Engine) passwordIdentifiers(ctx context.Context, userID string) ([]string, error) {
	u, err := s.getUserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) || u == nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, v := range []*string{u.Username, u.Email} {
		if v != nil {
			ids = append(ids, *v)
		}
	}
	return ids, nil
}

// validateUsernameForUser validates a desired username and confirms no OTHER
// live user already holds it, so username uniqueness is the only constraint.
// The returned slug is the lowercased username; excludeGroupID is retained in
// the signature for dependent adapters but is always empty under the
// permission-group model.
func (s *Engine) validateUsernameForUser(ctx context.Context, username, userID string) (slug, excludeGroupID string, err error) {
	if err := s.ValidateUsername(username); err != nil {
		return "", "", err
	}
	slug = strings.ToLower(strings.TrimSpace(username))
	if s.pg == nil {
		return slug, "", nil
	}
	existing, err := s.getUserByUsername(ctx, username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}
	if existing != nil && strings.TrimSpace(existing.ID) != strings.TrimSpace(userID) {
		return "", "", errmodel.E(errmodel.CodeUsernameInUse)
	}
	return slug, "", nil
}

func (s *Engine) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	slug, _, err := s.validateUsernameForUser(ctx, username, "")
	return slug, err
}
