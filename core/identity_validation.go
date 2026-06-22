package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/password"
)

const (
	ErrCodeUsernameTooShort            = "username_too_short"
	ErrCodeUsernameTooLong             = "username_too_long"
	ErrCodeUsernameMustStartWithLetter = "username_must_start_with_letter"
	ErrCodeUsernameCannotContainAt     = "username_cannot_contain_at"
	ErrCodeUsernameCannotStartWithPlus = "username_cannot_start_with_plus"
	ErrCodeUsernameInvalidCharacters   = "username_invalid_characters"
	ErrCodeOwnerSlugTaken              = "owner_slug_taken"
	ErrCodeUsernameNotAllowed          = "username_not_allowed"
	ErrCodeRenameRateLimited           = "rename_rate_limited"
	ErrCodeInvalidEmail                = "invalid_email"
	ErrCodeInvalidPhoneNumber          = "invalid_phone_number"
	ErrCodePasswordTooShort            = "password_too_short"
)

// ValidationError is the stable identity-policy error returned by AuthKit
// validation helpers. Code is intended to be exposed directly in route
// responses as {"error":"code"}.
type ValidationError struct {
	Code              string
	RetryAfterSeconds int64
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func newValidationError(code string) *ValidationError {
	return &ValidationError{Code: code}
}

// ValidationErrorCode returns a stable validation code from err when possible.
func ValidationErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr.Code
	}
	if errors.Is(err, ErrOwnerSlugTaken) {
		return ErrCodeOwnerSlugTaken
	}
	if errors.Is(err, ErrRenameRateLimited) {
		return ErrCodeRenameRateLimited
	}
	switch err.Error() {
	case ErrCodePasswordTooShort,
		ErrCodeUsernameTooShort,
		ErrCodeUsernameTooLong,
		ErrCodeUsernameMustStartWithLetter,
		ErrCodeUsernameCannotContainAt,
		ErrCodeUsernameCannotStartWithPlus,
		ErrCodeUsernameInvalidCharacters,
		ErrCodeInvalidEmail,
		"invalid_preferred_locale",
		ErrCodeInvalidPhoneNumber:
		return err.Error()
	default:
		return ""
	}
}

// Username length bounds shared by ValidateUsername and the automatic
// derivation in cleanUsername, so derived usernames always pass validation.
const (
	usernameMinLen = 4
	usernameMaxLen = 30
)

func ValidateUsername(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < usernameMinLen {
		return newValidationError(ErrCodeUsernameTooShort)
	}
	if len(username) > usernameMaxLen {
		return newValidationError(ErrCodeUsernameTooLong)
	}
	first := username[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return newValidationError(ErrCodeUsernameMustStartWithLetter)
	}
	if strings.Contains(username, "@") {
		return newValidationError(ErrCodeUsernameCannotContainAt)
	}
	if strings.HasPrefix(username, "+") {
		return newValidationError(ErrCodeUsernameCannotStartWithPlus)
	}
	for i := 0; i < len(username); i++ {
		ch := username[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_':
		default:
			return newValidationError(ErrCodeUsernameInvalidCharacters)
		}
	}
	return nil
}

// importUsernameMaxLen bounds operator-provisioned usernames. The import /
// bootstrap path is for operator-provisioned identities and historically
// accepted the slug shape (lowercase alnum + internal hyphens), unlike the
// stricter interactive-registration ValidateUsername. There is no DB-level
// length cap (username is citext), so this is the only bound.
const importUsernameMaxLen = 64

// validateImportUsername validates an OPERATOR-provisioned username (ImportUser /
// bootstrap manifest). It is deliberately more permissive than ValidateUsername:
// it also accepts hyphens (the historical slug shape) and a larger length cap,
// because these names are minted by an operator, not chosen interactively. It
// still requires a letter prefix and rejects '@' / leading '+' (login-identifier
// ambiguity).
func validateImportUsername(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < usernameMinLen {
		return newValidationError(ErrCodeUsernameTooShort)
	}
	if len(username) > importUsernameMaxLen {
		return newValidationError(ErrCodeUsernameTooLong)
	}
	first := username[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return newValidationError(ErrCodeUsernameMustStartWithLetter)
	}
	if strings.Contains(username, "@") {
		return newValidationError(ErrCodeUsernameCannotContainAt)
	}
	if strings.HasPrefix(username, "+") {
		return newValidationError(ErrCodeUsernameCannotStartWithPlus)
	}
	for i := 0; i < len(username); i++ {
		ch := username[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_':
		case ch == '-':
		default:
			return newValidationError(ErrCodeUsernameInvalidCharacters)
		}
	}
	return nil
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateEmail(email string) error {
	email = NormalizeEmail(email)
	if email == "" || strings.ContainsAny(email, " \t\r\n") {
		return newValidationError(ErrCodeInvalidEmail)
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') || at == len(email)-1 {
		return newValidationError(ErrCodeInvalidEmail)
	}
	domain := email[at+1:]
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return newValidationError(ErrCodeInvalidEmail)
	}
	return nil
}

func NormalizePhone(phone string) string {
	return strings.TrimSpace(phone)
}

func ValidatePhone(phone string) error {
	phone = NormalizePhone(phone)
	if len(phone) < 3 || len(phone) > 16 || phone[0] != '+' {
		return newValidationError(ErrCodeInvalidPhoneNumber)
	}
	if phone[1] < '1' || phone[1] > '9' {
		return newValidationError(ErrCodeInvalidPhoneNumber)
	}
	for i := 2; i < len(phone); i++ {
		if phone[i] < '0' || phone[i] > '9' {
			return newValidationError(ErrCodeInvalidPhoneNumber)
		}
	}
	return nil
}

func ValidatePassword(value string) error {
	if err := password.Validate(value); err != nil {
		return newValidationError(ErrCodePasswordTooShort)
	}
	return nil
}

// ValidateUsernameForUser validates a desired username and confirms no OTHER
// live user already holds it (#111: the org-slug reservation plane was removed,
// so username uniqueness is the only constraint). The returned slug is the
// lowercased username; excludeOrgID is retained in the signature for dependent
// adapters but is always empty under the permission-group model.
// Deprecated: use s.Users().ValidateUsernameForUser.
func (s *Service) ValidateUsernameForUser(ctx context.Context, username, userID string) (slug, excludeOrgID string, err error) {
	if err := ValidateUsername(username); err != nil {
		return "", "", err
	}
	slug = strings.ToLower(strings.TrimSpace(username))
	if s == nil || s.pg == nil {
		return slug, "", nil
	}
	existing, err := s.getUserByUsername(ctx, username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}
	if existing != nil && strings.TrimSpace(existing.ID) != strings.TrimSpace(userID) {
		return "", "", newValidationError(ErrCodeOwnerSlugTaken)
	}
	return slug, "", nil
}

// Deprecated: use s.Users().ValidateUsernameForRegistration.
func (s *Service) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	slug, _, err := s.ValidateUsernameForUser(ctx, username, "")
	return slug, err
}

// Deprecated: use s.Users().TimeUntilUsernameRenameAvailable.
func (s *Service) TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error) {
	if s == nil || s.pg == nil || strings.TrimSpace(userID) == "" {
		return 0, nil
	}
	var lastRenamedAt *time.Time
	if v, err := s.q.UserLastRenamedAt(ctx, strings.TrimSpace(userID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	} else {
		lastRenamedAt = &v
	}
	if lastRenamedAt == nil || lastRenamedAt.IsZero() {
		return 0, nil
	}
	availableAt := lastRenamedAt.Add(renameCooldown)
	if !availableAt.After(now) {
		return 0, nil
	}
	remaining := availableAt.Sub(now)
	return int64((remaining + time.Second - time.Nanosecond) / time.Second), nil
}
