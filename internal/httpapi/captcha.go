package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// maxCaptchaToken bounds a widget's token (Turnstile's are at most 2048).
const maxCaptchaToken = 4096

// humanProven checks Deps.Captcha's challenge before a start that texts or
// emails a code to an address the caller names, so bots cannot pump texts
// through it. It writes the refusal and reports false: captcha_failed for a
// missing or refused token, captcha_unavailable when the provider could not
// tell (it fails closed).
func (s *Service) humanProven(w http.ResponseWriter, r *http.Request, token string) bool {
	if s.captcha == nil {
		return true
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxCaptchaToken {
		s.fail(w, errmodel.CodeCaptchaFailed)
		return false
	}
	err := s.captcha.Verify(r.Context(), token, s.requestIP(r))
	switch {
	case err == nil:
		return true
	case errors.Is(err, iam.ErrCaptchaFailed):
		s.fail(w, errmodel.CodeCaptchaFailed)
	default:
		s.log.WarnContext(r.Context(), "authkit: the captcha provider could not check a token", "error", err)
		s.fail(w, errmodel.CodeCaptchaUnavailable)
	}
	return false
}
