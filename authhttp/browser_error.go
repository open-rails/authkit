package authhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
func (s *Service) failBrowserFlow(w http.ResponseWriter, r *http.Request, sd *oidckit.StateData, provider string, status int, code ErrorCode) {
	s.failBrowserFlowExtra(w, r, sd, provider, status, code, nil)
}

// failBrowserFlowExtra is failBrowserFlow with additional payload fields
// carried to the frontend (fragment params / postMessage keys) — e.g. the
// 2FA-enrollment token. Values must already be safe to hand to the SPA.
func (s *Service) failBrowserFlowExtra(w http.ResponseWriter, r *http.Request, sd *oidckit.StateData, provider string, status int, code ErrorCode, extra url.Values) {
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
			for k := range extra {
				payload[k] = extra.Get(k)
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
	for k := range extra {
		v.Set(k, extra.Get(k))
	}
	target := buildFrontendCallbackURL(s.svc.Config().Frontend.BaseURL, s.svc.Config().Frontend.OIDCReturnPath, "#"+v.Encode())
	http.Redirect(w, r, target, http.StatusFound)
}

// writePopupDocument writes a self-posting popup HTML document with the CSP
// that confines it to its inline script (shared by the success and error
// popup emissions).
func writePopupDocument(w http.ResponseWriter, html []byte) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
func sanitizeProviderErrorCode(raw string) ErrorCode {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || len(raw) > 64 {
		return ErrProviderError
	}
	for _, c := range raw {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return ErrProviderError
		}
	}
	return ErrorCode(raw)
}

// recoverCallbackState loads flow context for a callback that carries a usable
// state even though the IdP reported an error (state is echoed on error
// redirects too). The state cookie must match — a mismatched cookie means this
// browser did not start the flow, and no context may be recovered for it.
// Consuming here also burns the one-time state on the error path.
func (s *Service) recoverCallbackState(w http.ResponseWriter, r *http.Request, provider string) *oidckit.StateData {
	state := r.URL.Query().Get("state")
	if strings.TrimSpace(state) == "" || !stateCookieMatches(r, state) {
		return nil
	}
	clearStateCookie(w)
	sd, ok, err := consumeState(r.Context(), s.stateCache(), state)
	if err != nil || !ok || sd.Provider != provider {
		return nil
	}
	return &sd
}

// browser2FAEnrollmentRequired is write2FAEnrollmentRequired for browser
// navigations: the enrollment token rides the error contract (fragment or
// popup payload) as enrollment_token — deliberately NOT access_token, so a
// frontend that only looks for access_token treats the login as failed
// instead of storing an enrollment-scoped token as a real session.
func (s *Service) browser2FAEnrollmentRequired(w http.ResponseWriter, r *http.Request, userID, provider string, sd oidckit.StateData) {
	if wantsJSONResponse(r) {
		s.write2FAEnrollmentRequired(w, r, userID)
		return
	}
	token, exp, err := s.svc.Mint2FAEnrollmentToken(r.Context(), userID)
	if err != nil {
		s.failBrowserFlow(w, r, &sd, provider, http.StatusInternalServerError, ErrTokenIssueFailed)
		return
	}
	extra := url.Values{}
	extra.Set("enrollment_token", token)
	extra.Set("enrollment_expires_in", fmt.Sprint(int64(time.Until(exp).Seconds())))
	if methods := s.svc.TwoFactorAllowedMethods(); len(methods) > 0 {
		extra.Set("allowed_methods", strings.Join(methods, ","))
	}
	s.failBrowserFlowExtra(w, r, &sd, provider, http.StatusForbidden, ErrTwoFAEnrollmentRequired, extra)
}
