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
		ErrCodeInvalidPhoneNumber:
		return err.Error()
	default:
		return ""
	}
}

func ValidateUsername(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < 4 {
		return newValidationError(ErrCodeUsernameTooShort)
	}
	if len(username) > 30 {
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

func OwnerSlugFromUsername(username string) string {
	return ownerSlugFromUsername(username)
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

func UsernameOwnerNamespaceError(lookup *OwnerNamespaceLookup, allowedUserID string) string {
	if lookup == nil || lookup.Status == OwnerNamespaceStatusUnregistered {
		return ""
	}
	allowedUserID = strings.TrimSpace(allowedUserID)
	switch lookup.Status {
	case OwnerNamespaceStatusRegisteredUser:
		if allowedUserID != "" && lookup.User != nil && strings.TrimSpace(lookup.User.ID) == allowedUserID {
			return ""
		}
		return ErrCodeOwnerSlugTaken
	case OwnerNamespaceStatusRegisteredOrg:
		if allowedUserID != "" && lookup.Org != nil && strings.TrimSpace(lookup.Org.OwnerUserID) == allowedUserID {
			return ""
		}
		return ErrCodeOwnerSlugTaken
	case OwnerNamespaceStatusParkedUser,
		OwnerNamespaceStatusParkedOrg,
		OwnerNamespaceStatusRestrictedName:
		return ErrCodeUsernameNotAllowed
	case OwnerNamespaceStatusRenamedUser,
		OwnerNamespaceStatusRenamedOrg,
		OwnerNamespaceStatusHeldByDeletedUser,
		OwnerNamespaceStatusHeldByDeletedOrg,
		OwnerNamespaceStatusHeldByRecentUserRename,
		OwnerNamespaceStatusHeldByRecentOrgRename:
		return ErrCodeOwnerSlugTaken
	default:
		if !lookup.Claimable {
			return ErrCodeOwnerSlugTaken
		}
		return ""
	}
}

func (s *Service) ValidateUsernameForUser(ctx context.Context, username, userID string) (slug, excludeOrgID string, err error) {
	if err := ValidateUsername(username); err != nil {
		return "", "", err
	}
	slug = OwnerSlugFromUsername(username)
	if slug == "" || validateOrgSlug(slug) != nil {
		return "", "", newValidationError(ErrCodeUsernameInvalidCharacters)
	}
	if s == nil || s.pg == nil {
		return slug, "", nil
	}
	lookup, err := s.LookupOwnerNamespace(ctx, slug)
	if err != nil {
		return "", "", err
	}
	if code := UsernameOwnerNamespaceError(lookup, userID); code != "" {
		return "", "", newValidationError(code)
	}
	if lookup != nil && lookup.Org != nil && strings.TrimSpace(lookup.Org.OwnerUserID) == strings.TrimSpace(userID) {
		excludeOrgID = strings.TrimSpace(lookup.Org.ID)
	}
	return slug, excludeOrgID, nil
}

func (s *Service) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	slug, _, err := s.ValidateUsernameForUser(ctx, username, "")
	return slug, err
}

func (s *Service) TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error) {
	if s == nil || s.pg == nil || strings.TrimSpace(userID) == "" {
		return 0, nil
	}
	var lastRenamedAt *time.Time
	if err := s.pg.QueryRow(ctx, `
		SELECT renamed_at
		FROM   profiles.user_renames
		WHERE  user_id = $1::uuid
		ORDER  BY renamed_at DESC
		LIMIT  1
	`, strings.TrimSpace(userID)).Scan(&lastRenamedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
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

func (s *Service) TimeUntilOrgRenameAvailable(ctx context.Context, orgID string, now time.Time) (int64, error) {
	if s == nil || s.pg == nil || strings.TrimSpace(orgID) == "" {
		return 0, nil
	}
	var lastRenamedAt *time.Time
	if err := s.pg.QueryRow(ctx, `
		SELECT renamed_at
		FROM   profiles.org_renames
		WHERE  org_id = $1::uuid
		ORDER  BY renamed_at DESC
		LIMIT  1
	`, strings.TrimSpace(orgID)).Scan(&lastRenamedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
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
