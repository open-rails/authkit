package embedded

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/password"
)

// validationCodes are the identity-policy codes ValidationErrorCode reports:
// a 400 whose param names the offending field.
var validationCodes = map[authkit.Code]bool{
	authkit.CodeUsernameTooShort: true, authkit.CodeUsernameTooLong: true, authkit.CodeUsernameMustStartWithLetter: true,
	authkit.CodeUsernameCannotContainAt: true, authkit.CodeUsernameCannotStartWithPlus: true, authkit.CodeUsernameInvalidCharacters: true,
	authkit.CodeOwnerSlugTaken: true, authkit.CodeUsernameNotAllowed: true, authkit.CodeRenameRateLimited: true,
	authkit.CodeInvalidEmail: true, authkit.CodeInvalidPhoneNumber: true, authkit.CodePasswordTooShort: true,
	authkit.CodeInvalidPreferredLanguage: true,
}

// ValidationErrorCode returns the identity-policy code err carries, or "" when
// err is not a validation failure.
func ValidationErrorCode(err error) authkit.Code {
	if e := authkit.AsError(err); e != nil && validationCodes[e.Code] {
		return e.Code
	}
	return ""
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
		return authkit.E(authkit.CodeUsernameTooShort)
	}
	if len(username) > usernameMaxLen {
		return authkit.E(authkit.CodeUsernameTooLong)
	}
	first := username[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return authkit.E(authkit.CodeUsernameMustStartWithLetter)
	}
	if strings.Contains(username, "@") {
		return authkit.E(authkit.CodeUsernameCannotContainAt)
	}
	if strings.HasPrefix(username, "+") {
		return authkit.E(authkit.CodeUsernameCannotStartWithPlus)
	}
	for i := 0; i < len(username); i++ {
		ch := username[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_':
		default:
			return authkit.E(authkit.CodeUsernameInvalidCharacters)
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
		return authkit.E(authkit.CodeUsernameTooShort)
	}
	if len(username) > importUsernameMaxLen {
		return authkit.E(authkit.CodeUsernameTooLong)
	}
	first := username[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return authkit.E(authkit.CodeUsernameMustStartWithLetter)
	}
	if strings.Contains(username, "@") {
		return authkit.E(authkit.CodeUsernameCannotContainAt)
	}
	if strings.HasPrefix(username, "+") {
		return authkit.E(authkit.CodeUsernameCannotStartWithPlus)
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
			return authkit.E(authkit.CodeUsernameInvalidCharacters)
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
		return authkit.E(authkit.CodeInvalidEmail)
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') || at == len(email)-1 {
		return authkit.E(authkit.CodeInvalidEmail)
	}
	domain := email[at+1:]
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return authkit.E(authkit.CodeInvalidEmail)
	}
	return nil
}

func NormalizePhone(phone string) string {
	return strings.TrimSpace(phone)
}

func ValidatePhone(phone string) error {
	phone = NormalizePhone(phone)
	if len(phone) < 3 || len(phone) > 16 || phone[0] != '+' {
		return authkit.E(authkit.CodeInvalidPhoneNumber)
	}
	if phone[1] < '1' || phone[1] > '9' {
		return authkit.E(authkit.CodeInvalidPhoneNumber)
	}
	for i := 2; i < len(phone); i++ {
		if phone[i] < '0' || phone[i] > '9' {
			return authkit.E(authkit.CodeInvalidPhoneNumber)
		}
	}
	return nil
}

func ValidatePassword(value string) error {
	if err := password.Validate(value); err != nil {
		return authkit.E(authkit.CodePasswordTooShort)
	}
	return nil
}

// validateUsernameForUser validates a desired username and confirms no OTHER
// live user already holds it, so username uniqueness is the only constraint.
// The returned slug is the lowercased username; excludeGroupID is retained in
// the signature for dependent adapters but is always empty under the
// permission-group model.
func (s *Client) validateUsernameForUser(ctx context.Context, username, userID string) (slug, excludeGroupID string, err error) {
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
		return "", "", authkit.E(authkit.CodeOwnerSlugTaken)
	}
	return slug, "", nil
}

func (s *Client) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	slug, _, err := s.validateUsernameForUser(ctx, username, "")
	return slug, err
}
