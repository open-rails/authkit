package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/password"
)

// ValidateUsername applies the configured username policy and fixed
// iam.UsernamePattern.
func (s *Engine) ValidateUsername(username string) error {
	return s.cfg.Username.Validate(username)
}

// ValidatePassword applies the configured password policy. identifiers are
// the account's username and email address when known. Length failures carry
// min_length/max_length; requirement failures carry the missing classes.
func (s *Engine) ValidatePassword(value string, identifiers ...string) error {
	return validatePassword(password.Policy(s.cfg.Password), value, identifiers...)
}

func validatePassword(p password.Policy, value string, identifiers ...string) error {
	ids := make([]string, 0, len(identifiers))
	for _, id := range identifiers {
		if local := password.EmailLocalPart(id); local != "" {
			id = local
		}
		ids = append(ids, id)
	}
	err := p.Validate(value, ids...)
	var unmet *password.RequirementsError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &unmet):
		return iam.E(iam.CodePasswordRequirementsUnmet, iam.WithMeta("missing", unmet.Missing))
	case errors.Is(err, password.ErrTooCommon):
		return iam.E(iam.CodePasswordTooCommon)
	case errors.Is(err, password.ErrContainsIdentifier):
		return iam.E(iam.CodePasswordContainsIdentifier)
	}
	code := iam.CodePasswordTooShort
	if errors.Is(err, password.ErrTooLong) {
		code = iam.CodePasswordTooLong
	}
	return iam.E(code, iam.WithMetadata(map[string]any{"min_length": p.MinLength, "max_length": p.MaxLength}))
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
		return "", "", iam.E(iam.CodeOwnerSlugTaken)
	}
	return slug, "", nil
}

func (s *Engine) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	slug, _, err := s.validateUsernameForUser(ctx, username, "")
	return slug, err
}
