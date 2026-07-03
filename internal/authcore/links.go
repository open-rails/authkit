package authcore

import (
	"net/url"
	"strings"
)

// URL builders for the links AuthKit emails/texts: verification, password
// reset, and passwordless landing pages. All resolve against the host's
// configured BaseURL and frontend paths.

func (s *Service) authkitURL(path string, q url.Values) string {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.Frontend.BaseURL), "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	out := base + path
	if encoded := q.Encode(); encoded != "" {
		out += "?" + encoded
	}
	return out
}

// verificationURL builds the host-facing link AuthKit emails for a
// verification/reset flow: BaseURL + a host-configured FRONTEND landing path +
// ?token=...&channel=email|phone. The frontend page reads the token (and
// channel) and POSTs to the matching confirm endpoint (the SPA-link model,
// #131). The landing path is configurable (FrontendVerifyPath /
// FrontendPasswordResetPath) so a host keeps its own routes; channel lets one
// landing page serve both email and phone. Verify and reset are symmetric: same
// mechanism, different configured path.
func (s *Service) verificationURL(frontendPath, channel, token string) string {
	q := url.Values{}
	q.Set("token", token)
	if channel != "" {
		q.Set("channel", channel)
	}
	return s.authkitURL(frontendPath, q)
}

func (s *Service) emailVerificationURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.VerifyPath, "email", token)
}

func (s *Service) phoneVerificationURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.VerifyPath, "phone", token)
}

func (s *Service) emailPasswordResetURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.PasswordResetPath, "email", token)
}

func (s *Service) phonePasswordResetURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.PasswordResetPath, "phone", token)
}

func (s *Service) passwordlessURL(channel, token, returnTo string) string {
	q := url.Values{}
	q.Set("token", token)
	if channel != "" {
		q.Set("channel", channel)
	}
	if safe := sanitizePasswordlessReturnTo(returnTo); safe != "" {
		q.Set("return_to", safe)
	}
	return s.authkitURL(s.cfg.Frontend.PasswordlessPath, q)
}
