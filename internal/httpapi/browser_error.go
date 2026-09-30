package httpapi

import (
	"encoding/json"
	stdlog "log"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/oidcstate"
	"github.com/open-rails/authkit/provider"
)

// Browser-flow error propagation.
//
// The GET routes under /oidc ({provider}/login, {provider}/callback,
// {provider}/step-up/callback) are top-level browser navigations — or popup
// windows the frontend opened onto them — not fetch calls. Writing a JSON
// error envelope to them strands the user on the backend URL with a raw JSON
// body, and a popup opener waits forever for a result message that never
// comes. Errors on these routes are therefore emitted the same way successes
// are:
//
//   - format=json / Accept: application/json — the JSON envelope, unchanged.
//     Programmatic callers and tests keep the legacy contract.
//   - step-up flows (StateData.StepUpUserID set) — redirect to the flow's
//     sanitized return_to with ?step_up=failed, exactly like every
//     post-consume step-up failure already does (redirectStepUpResult).
//   - popup flows (ui=popup) — a postMessage document targeting the frontend
//     origin, type AUTHKIT_OIDC_ERROR. The type is deliberately DISTINCT from
//     the success type (AUTHKIT_OIDC_RESULT) so pre-existing openers that only
//     understand the success shape ignore the message instead of misreading an
//     error as a login. The popup nonce rides along for opener validation.
//   - everything else — 302 to Frontend BaseURL+OIDCReturnPath with the error
//     in the URL FRAGMENT (#error=<code>&flow=login|link&provider=…
//     [&return_to=…]), mirroring how tokens are delivered on success. The
//     fragment (not the query) keeps error codes out of access logs and
//     Referer headers, and lands on the exact SPA route that already parses
//     login-result fragments.
//
// Rate-limit rejections (429) are deliberately left on the JSON path: they are
// an abuse defense with Retry-After header semantics, not a user-flow outcome,
// and the shared limiter helper serves every route group.
func (s *Service) failBrowserFlow(w http.ResponseWriter, r *http.Request, sd *oidcstate.StateData, provider string, err error) {
	s.failBrowserFlowExtra(w, r, sd, provider, err, nil)
}

// failBrowserFlowExtra is failBrowserFlow with additional payload fields
// carried to the frontend (fragment params / postMessage keys) — e.g. the
// 2FA-enrollment token. Values must already be safe to hand to the SPA.
func (s *Service) failBrowserFlowExtra(w http.ResponseWriter, r *http.Request, sd *oidcstate.StateData, provider string, err error, extra map[string]any) {
	if wantsJSONResponse(r) {
		writeError(w, err)
		return
	}
	code := browserErrorCode(err)
	if sd != nil && strings.TrimSpace(sd.StepUpUserID) != "" {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return
	}

	// Flow context comes from the consumed state when the callback got that
	// far; start-handler failures happen before any StateData exists, so the
	// popup marker is still on the request itself.
	ui, popupNonce, returnTo, flow := "", "", "", "login"
	if sd != nil {
		ui, popupNonce, returnTo = sd.UI, sd.PopupNonce, sd.ReturnTo
		if strings.TrimSpace(sd.LinkUserID) != "" {
			flow = "link"
		}
	} else {
		q := r.URL.Query()
		ui, popupNonce, returnTo = q.Get("ui"), q.Get("popup_nonce"), q.Get("return_to")
	}

	if ui == "popup" {
		if targetOrigin, ok := originFromBaseURL(s.settings.FrontendBaseURL); ok {
			payload := map[string]any{
				"type":     "AUTHKIT_OIDC_ERROR",
				"error":    code,
				"provider": provider,
				"flow":     flow,
				"nonce":    popupNonce,
			}
			for key, value := range extra {
				payload[key] = value
			}
			b, _ := json.Marshal(payload)
			writePopupDocument(w, buildPopupHTML(b, targetOrigin))
			return
		}
		// No parseable frontend origin to postMessage to — fall through to the
		// fragment redirect, which tolerates a relative base.
	}

	v := url.Values{}
	v.Set("error", code)
	v.Set("flow", flow)
	if strings.TrimSpace(provider) != "" {
		v.Set("provider", provider)
	}
	if rt := SanitizeReturnTo(returnTo); rt != "/" {
		v.Set("return_to", rt)
	}
	for key, value := range extra {
		if text, ok := value.(string); ok {
			v.Set(key, text)
		} else {
			raw, _ := json.Marshal(value)
			v.Set(key, string(raw))
		}
	}
	target := buildFrontendCallbackURL(s.settings.FrontendBaseURL, s.settings.OIDCReturnPath, "#"+v.Encode())
	// RFC 6749 §5.1 hygiene: flow results must never be cached — the Location
	// fragment can carry an enrollment token (and its success sibling carries
	// session tokens).
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// writePopupDocument writes a self-posting popup HTML document with the CSP
// that confines it to its inline script (shared by the success and error
// popup emissions). The document embeds flow results (tokens on success), so
// it is marked uncacheable (RFC 6749 §5.1).
func writePopupDocument(w http.ResponseWriter, html []byte) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(html)
}

// wantsJSONResponse mirrors the success-path content negotiation
// (finishBrowserLogin, emitStepUpResult): explicit format=json or an Accept
// header naming application/json keeps the JSON contract.
func wantsJSONResponse(r *http.Request) bool {
	return strings.EqualFold(r.URL.Query().Get("format"), "json") ||
		strings.Contains(r.Header.Get("Accept"), "application/json")
}

// providerCallbackError is the IdP-reported ?error= as provider_error. The
// echoed value is semi attacker-controlled (anyone can craft a callback URL),
// so it is clamped to a conservative token charset before it is reflected:
// RFC 6749 codes (access_denied, invalid_scope, ...) pass through to the
// browser fragment or popup payload, and the JSON envelope carries them as
// metadata.provider_error; anything else collapses to provider_error.
func providerCallbackError(raw string) error {
	code := strings.ToLower(strings.TrimSpace(raw))
	if code == "" || len(code) > 64 || strings.IndexFunc(code, func(c rune) bool {
		return (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.'
	}) >= 0 {
		code = string(errmodel.CodeProviderError)
	}
	return errmodel.E(errmodel.CodeProviderError, errmodel.WithMeta("provider_error", code))
}

// browserErrorCode is the code a browser flow hands the SPA: the wire code, or
// the IdP's own code for a provider callback error.
func browserErrorCode(err error) string {
	e := errmodel.Wire(err)
	if raw, ok := e.Metadata()["provider_error"].(string); ok && errmodel.CodeOf(err) == errmodel.CodeProviderError {
		return raw
	}
	return e.Code()
}

// logIdPCallbackError records the raw provider-reported callback error for
// diagnostics. The raw values are semi attacker-controlled (anyone can craft
// a callback URL), so they are %q-quoted and truncated — logged, never
// reflected: the wire code the user sees is providerCallbackError's
// output.
func logIdPCallbackError(provider string, r *http.Request) {
	q := callbackParams(r)
	stdlog.Printf("[authkit/oidc] provider callback error (provider=%q): error=%q error_description=%q error_uri=%q",
		truncateForLog(provider, 64),
		truncateForLog(q.Get("error"), 200),
		truncateForLog(q.Get("error_description"), 200),
		truncateForLog(q.Get("error_uri"), 200))
}

func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// recoverCallbackState loads flow context for a callback that carries a usable
// state even though the IdP reported an error (state is echoed on error
// redirects too). The state cookie must match — a mismatched cookie means this
// browser did not start the flow, and no context may be recovered for it.
// Consuming here also burns the one-time state on the error path.
func (s *Service) recoverCallbackState(w http.ResponseWriter, r *http.Request, p provider.Provider) *oidcstate.StateData {
	state := callbackParams(r).Get("state")
	if strings.TrimSpace(state) == "" || !s.stateCookieMatches(r, p, state) {
		return nil
	}
	s.clearStateCookie(w, r, p, state)
	sd, ok, err := s.svc.ConsumeOIDCState(r.Context(), state)
	if err != nil || !ok || sd.Provider != p.Name() {
		return nil
	}
	return &sd
}

// Browser and JSON callbacks present the same engine-produced continuation.
func (s *Service) browserLoginContinuation(w http.ResponseWriter, r *http.Request, out authflow.LoginOutcome, provider string, sd oidcstate.StateData) {
	out.ReturnTo = sd.ReturnTo
	if wantsJSONResponse(r) {
		s.writeLoginContinuation(w, r, out, nil)
		return
	}
	var extra map[string]any
	code := errmodel.CodeTwoFAEnrollmentRequired
	if out.Kind == authflow.LoginRecoveryRequired {
		s.failBrowserFlowExtra(w, r, &sd, provider, errmodel.E(errmodel.CodeAccountRecoveryRequired), map[string]any{"recovery": out.Recovery})
		return
	} else if out.Kind == authflow.LoginTwoFactorRequired {
		code = errmodel.CodeTwoFARequired
		extra = loginChallengeMetadata(out.UserID, out.Challenge)
	} else {
		extra = map[string]any{"user_id": out.UserID, "enrollment_token": out.Enrollment.AccessToken, "enrollment_expires_in": out.Enrollment.ExpiresIn, "allowed_methods": out.AllowedMethods}
	}
	s.failBrowserFlowExtra(w, r, &sd, provider, errmodel.E(code), extra)
}
