package embedded

import (
	"net/url"
	"strings"
)

// URL builders for the links AuthKit emails/texts: verification, password
// reset, and passwordless landing pages. All resolve against the host's
// configured BaseURL and frontend paths.

func (s *Runtime) authkitURL(path string, q url.Values) string {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.Frontend.BaseURL), "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	out := base + path
	if encoded := q.Encode(); encoded != "" {
		out += "#" + encoded
	}
	return out
}

// verificationURL builds the host-facing link AuthKit emails for a
// verification/reset flow: BaseURL + a host-configured FRONTEND landing path +
// #status=ready&token=...&channel=email|phone. The frontend page reads the token (and
// channel) and POSTs to the matching confirm endpoint (the SPA-link model,
// #131). The landing path is configurable (FrontendVerifyPath /
// FrontendPasswordResetPath) so a host keeps its own routes; channel lets one
// landing page serve both email and phone. Verify and reset are symmetric: same
// mechanism, different configured path.
func (s *Runtime) verificationURL(frontendPath, channel, token string) string {
	q := url.Values{}
	q.Set("status", "ready")
	q.Set("token", token)
	if channel != "" {
		q.Set("channel", channel)
	}
	return s.authkitURL(frontendPath, q)
}

func (s *Runtime) emailVerificationURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.VerifyPath, "email", token)
}

func (s *Runtime) phoneVerificationURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.VerifyPath, "phone", token)
}

func (s *Runtime) emailPasswordResetURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.PasswordResetPath, "email", token)
}

func (s *Runtime) phonePasswordResetURL(token string) string {
	return s.verificationURL(s.cfg.Frontend.PasswordResetPath, "phone", token)
}

func (s *Runtime) passwordlessURL(channel, token, returnTo string) string {
	q := url.Values{}
	q.Set("status", "ready")
	q.Set("token", token)
	if channel != "" {
		q.Set("channel", channel)
	}
	if safe := sanitizePasswordlessReturnTo(returnTo); safe != "" {
		q.Set("return_to", safe)
	}
	return s.authkitURL(s.cfg.Frontend.PasswordlessPath, q)
}
