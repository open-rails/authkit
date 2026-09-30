package httpapi

import (
	stdlog "log"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/oidcstate"
	"github.com/open-rails/authkit/provider"
)

// Browser-flow errors land where the flow's results do. The /oidc routes are
// top-level navigations (or popups the page opened onto them), not fetch
// calls: a JSON envelope would strand the user on a raw body, and a popup's
// opener would wait forever.
//
//   - format=json / Accept: application/json: the error envelope.
//   - a step-up: back to its return_to with #error=<code>.
//   - a popup: {type: AUTHKIT_OIDC_RESULT, nonce, provider, error} posted to
//     the frontend origin.
//   - otherwise: to the app's OIDC return page with
//     #error=<code>&state=&flow=login|link&provider=[&return_to=], in the
//     fragment, which access logs and Referer never see.
//
// Rate-limit rejections (429) stay JSON: an abuse defense with Retry-After
// semantics, not a flow outcome.
func (s *Service) failBrowserFlow(w http.ResponseWriter, r *http.Request, sd *oidcstate.StateData, provider string, err error) {
	if wantsJSONResponse(r) {
		writeError(w, err)
		return
	}
	code := browserErrorCode(err)
	w.Header().Set("Cache-Control", "no-store")
	if sd != nil && strings.TrimSpace(sd.StepUpUserID) != "" {
		http.Redirect(w, r, stepUpReturnURL(sd.StepUpReturnTo, url.Values{"error": {code}}), http.StatusFound)
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

	// Without a parseable frontend origin to post to, a popup falls through to
	// the fragment redirect, which tolerates a relative base.
	if targetOrigin, ok := originFromBaseURL(s.cfg.Frontend.BaseURL); ok && ui == "popup" {
		writePopupDocument(w, buildPopupHTML(oidcPopupMessage{Type: oidcPopupType, Nonce: popupNonce, Provider: provider, Error: &code}, targetOrigin))
		return
	}

	v := url.Values{}
	v.Set("error", code)
	if state := callbackParams(r).Get("state"); state != "" {
		v.Set("state", state)
	}
	v.Set("flow", flow)
	if strings.TrimSpace(provider) != "" {
		v.Set("provider", provider)
	}
	if rt := SanitizeReturnTo(returnTo); rt != "/" {
		v.Set("return_to", rt)
	}
	http.Redirect(w, r, s.frontendCallbackURL("#"+v.Encode()), http.StatusFound)
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

// wantsJSONResponse: a callback asked for JSON (format=json, or an Accept
// naming application/json) answers the AuthResult or the error envelope.
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
	return errmodel.E(errmodel.CodeProviderError, errmodel.WithDetails(ProviderError{ProviderError: code}))
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
