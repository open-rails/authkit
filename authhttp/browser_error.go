package authhttp

import (
	"encoding/json"
	stdlog "log"
	"net/http"
	"net/url"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/oidckit"
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
func (s *Service) failBrowserFlow(w http.ResponseWriter, r *http.Request, sd *oidckit.StateData, provider string, status int, code authkit.Code) {
	s.failBrowserFlowExtra(w, r, sd, provider, status, code, nil)
}

// failBrowserFlowExtra is failBrowserFlow with additional payload fields
// carried to the frontend (fragment params / postMessage keys) — e.g. the
// 2FA-enrollment token. Values must already be safe to hand to the SPA.
func (s *Service) failBrowserFlowExtra(w http.ResponseWriter, r *http.Request, sd *oidckit.StateData, provider string, status int, code authkit.Code, extra map[string]any) {
	if wantsJSONResponse(r) {
		sendErr(w, status, code)
		return
	}
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
		if targetOrigin, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL); ok {
			payload := map[string]any{
				"type":     "AUTHKIT_OIDC_ERROR",
				"error":    string(code),
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
	v.Set("error", string(code))
	v.Set("flow", flow)
	if strings.TrimSpace(provider) != "" {
		v.Set("provider", provider)
	}
	if rt := sanitizeReturnTo(returnTo); rt != "/" {
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
	target := buildFrontendCallbackURL(s.svc.Config().Frontend.BaseURL, s.svc.Config().Frontend.OIDCReturnPath, "#"+v.Encode())
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

// sanitizeProviderErrorCode clamps the IdP-echoed ?error= value — semi
// attacker-controlled, since anyone can craft a callback URL — to a
// conservative token charset before it is reflected into a fragment, popup
// payload, or JSON envelope. RFC 6749 codes (access_denied, invalid_scope, …)
// pass through unchanged; anything else collapses to provider_error.
func sanitizeProviderErrorCode(raw string) authkit.Code {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || len(raw) > 64 {
		return authkit.CodeProviderError
	}
	for _, c := range raw {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return authkit.CodeProviderError
		}
	}
	return authkit.Code(raw)
}

// logIdPCallbackError records the raw provider-reported callback error for
// diagnostics. The raw values are semi attacker-controlled (anyone can craft
// a callback URL), so they are %q-quoted and truncated — logged, never
// reflected: the wire code the user sees is sanitizeProviderErrorCode's
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
func (s *Service) recoverCallbackState(w http.ResponseWriter, r *http.Request, p authprovider.Provider) *oidckit.StateData {
	state := callbackParams(r).Get("state")
	if strings.TrimSpace(state) == "" || !stateCookieMatches(r, state) {
		return nil
	}
	s.clearStateCookie(w, r, p, state)
	sd, ok, err := s.oidcStates.Consume(r.Context(), state)
	if err != nil || !ok || sd.Provider != p.Name() {
		return nil
	}
	return &sd
}

// Browser and JSON callbacks present the same engine-produced continuation.
func (s *Service) browserLoginContinuation(w http.ResponseWriter, r *http.Request, out embedded.LoginOutcome, provider string, sd oidckit.StateData) {
	out.ReturnTo = sd.ReturnTo
	if wantsJSONResponse(r) {
		s.writeLoginContinuation(w, r, out, nil)
		return
	}
	var extra map[string]any
	code := authkit.CodeTwoFAEnrollmentRequired
	if out.Kind == embedded.LoginRecoveryRequired {
		s.failBrowserFlowExtra(w, r, &sd, provider, http.StatusConflict, authkit.CodeAccountRecoveryRequired, map[string]any{"recovery": out.Recovery})
		return
	} else if out.Kind == embedded.LoginTwoFactorRequired {
		code = authkit.CodeTwoFARequired
		extra = loginChallengeMetadata(out.UserID, out.Challenge)
	} else {
		extra = map[string]any{"user_id": out.UserID, "enrollment_token": out.Enrollment.AccessToken, "enrollment_expires_in": out.Enrollment.ExpiresIn, "allowed_methods": out.AllowedMethods}
	}
	s.failBrowserFlowExtra(w, r, &sd, provider, http.StatusForbidden, code, extra)
}
