package embedded

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/password"
)

// validationCodes are the identity-policy codes ValidationErrorCode reports:
// a 400 whose param names the offending field.
var validationCodes = map[iam.Code]bool{
	iam.CodeUsernameTooShort: true, iam.CodeUsernameTooLong: true, iam.CodeUsernameMustStartWithLetter: true,
	iam.CodeUsernameCannotContainAt: true, iam.CodeUsernameCannotStartWithPlus: true, iam.CodeUsernameInvalidCharacters: true,
	iam.CodeOwnerSlugTaken: true, iam.CodeUsernameNotAllowed: true, iam.CodeRenameRateLimited: true,
	iam.CodeInvalidEmail: true, iam.CodeInvalidPhoneNumber: true, iam.CodePasswordTooShort: true, iam.CodePasswordTooLong: true,
	iam.CodePasswordTooCommon: true, iam.CodePasswordContainsIdentifier: true, iam.CodePasswordRequirementsUnmet: true,
	iam.CodeInvalidPreferredLanguage: true,
}

// ValidationErrorCode returns the identity-policy code err carries, or "" when
// err is not a validation failure.
func ValidationErrorCode(err error) iam.Code {
	if e := iam.AsError(err); e != nil && validationCodes[e.Code] {
		return e.Code
	}
	return ""
}

// ValidateUsername applies the configured username policy and fixed
// iam.UsernamePattern.
func (s *engine) ValidateUsername(username string) error {
	return s.cfg.Username.Validate(username)
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateEmail(email string) error {
	email = NormalizeEmail(email)
	if email == "" || strings.ContainsAny(email, " \t\r\n") {
		return iam.E(iam.CodeInvalidEmail)
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') || at == len(email)-1 {
		return iam.E(iam.CodeInvalidEmail)
	}
	domain := email[at+1:]
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return iam.E(iam.CodeInvalidEmail)
	}
	return nil
}

func NormalizePhone(phone string) string {
	return strings.TrimSpace(phone)
}

func ValidatePhone(phone string) error {
	phone = NormalizePhone(phone)
	if len(phone) < 3 || len(phone) > 16 || phone[0] != '+' {
		return iam.E(iam.CodeInvalidPhoneNumber)
	}
	if phone[1] < '1' || phone[1] > '9' {
		return iam.E(iam.CodeInvalidPhoneNumber)
	}
	for i := 2; i < len(phone); i++ {
		if phone[i] < '0' || phone[i] > '9' {
			return iam.E(iam.CodeInvalidPhoneNumber)
		}
	}
	return nil
}

// ValidatePassword applies the configured password policy. identifiers are
// the account's username and email address when known. Length failures carry
// min_length/max_length; requirement failures carry the missing classes.
func (s *engine) ValidatePassword(value string, identifiers ...string) error {
	return validatePassword(s.cfg.Password, value, identifiers...)
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
func (s *engine) passwordIdentifiers(ctx context.Context, userID string) ([]string, error) {
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
func (s *engine) validateUsernameForUser(ctx context.Context, username, userID string) (slug, excludeGroupID string, err error) {
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

func (s *engine) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	slug, _, err := s.validateUsernameForUser(ctx, username, "")
	return slug, err
}
