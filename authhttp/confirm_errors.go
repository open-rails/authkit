package authhttp

import (
	"errors"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// confirmBackendError reports whether a verify/reset confirm failure is the
// backend failing (ephemeral store, database) rather than a wrong code/token or
// a policy refusal. Backend failures are 500 and never counted as a guess, so a
// store blip cannot burn a user's live code (ak#324).
func confirmBackendError(err error) bool {
	if err == nil {
		return false
	}
	for _, known := range []error{jwt.ErrTokenUnverifiable, jwt.ErrTokenInvalidClaims, jwt.ErrTokenExpired, authkit.ErrRegistrationDisabled, authkit.ErrUserBanned} {
		if errors.Is(err, known) {
			return false
		}
	}
	return embedded.ValidationErrorCode(err) == ""
}

// confirmBackendFailed writes the 500 for a backend failure and reports whether
// it did; a wrong code/token returns false so the caller counts and maps it.
func (s *Service) confirmBackendFailed(w http.ResponseWriter, r *http.Request, route, stage string, err error) bool {
	if !confirmBackendError(err) {
		return false
	}
	s.logInternalError(r, route, stage, "database_error", err)
	serverErr(w, authkit.CodeDatabaseError)
	return true
}

// issueVerificationTokens is the shared success tail of the verify-confirm
// handlers: mint the session or map the mint failure.
func (s *Service) issueVerificationTokens(w http.ResponseWriter, r *http.Request, userID, method string) {
	if err := s.issueTokensForUser(w, r, userID, method); err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, authkit.CodeUserBanned)
			return
		}
		serverErr(w, authkit.CodeTokenIssueFailed)
	}
}
