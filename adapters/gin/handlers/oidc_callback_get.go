package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
)

func HandleOIDCCallbackGET(cfg OIDCConfig, svc core.Provider, exchanger func(ctx context.Context, rpClient rp.RelyingParty, provider, code, verifier, nonce string) (oidckit.Claims, error), rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLOIDCCallback) {
			ginutil.TooMany(c)
			return
		}
		if qErr := c.Query("error"); qErr != "" {
			ginutil.BadRequest(c, qErr)
			return
		}
		provider := c.Param("provider")
		state := c.Query("state")
		code := c.Query("code")
		if state == "" || code == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		sd, ok, err := cfg.StateCache.Get(c.Request.Context(), state)
		_ = cfg.StateCache.Del(c.Request.Context(), state)
		if err != nil || !ok || sd.Provider != provider {
			ginutil.BadRequest(c, "invalid_state")
			return
		}
		rpClient, err := cfg.Manager.GetRPWithRedirect(c.Request.Context(), provider, sd.RedirectURI)
		if err != nil {
			ginutil.BadRequest(c, "unknown_provider")
			return
		}
		issuer, ok := cfg.Manager.IssuerFor(provider)
		if !ok {
			ginutil.BadRequest(c, "unknown_provider")
			return
		}
		ex := exchanger
		if ex == nil {
			ex = oidckit.DefaultExchanger
		}
		claims, err := ex(c.Request.Context(), rpClient, provider, code, sd.Verifier, sd.Nonce)
		if err != nil {
			ginutil.Unauthorized(c, "oidc_exchange_failed")
			return
		}
		var userID, email string
		created := false
		if claims.Email != nil {
			email = *claims.Email
		}
		// Provider-preferred username if present
		provUsername := ""
		if claims.PreferredUsername != nil {
			provUsername = *claims.PreferredUsername
		}
		if sd.LinkUserID != "" {
			if uid0, _, err := svc.GetProviderLinkByIssuer(c.Request.Context(), issuer, claims.Subject); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
				c.JSON(http.StatusConflict, gin.H{"error": "provider_already_linked"})
				return
			}
			userID = sd.LinkUserID
			_ = svc.LinkProviderByIssuer(c.Request.Context(), userID, issuer, provider, claims.Subject, claims.Email)
			if strings.TrimSpace(provUsername) != "" {
				_ = svc.SetProviderUsername(c.Request.Context(), userID, issuer, claims.Subject, provUsername)
			}
		} else if uid, provEmail, err := svc.GetProviderLink(c.Request.Context(), provider, claims.Subject); err == nil && uid != "" {
			userID = uid
			if email == "" && provEmail != nil {
				email = *provEmail
			}
			if strings.TrimSpace(provUsername) != "" {
				_ = svc.SetProviderUsername(c.Request.Context(), userID, issuer, claims.Subject, provUsername)
			}
		} else {
			matched := false
			if claims.Email != nil && (claims.EmailVerified == nil || (claims.EmailVerified != nil && *claims.EmailVerified)) {
				if u, err := svc.GetUserByEmail(c.Request.Context(), email); err == nil && u != nil {
					userID = u.ID
					matched = true
					_ = svc.LinkProviderByIssuer(c.Request.Context(), u.ID, issuer, provider, claims.Subject, claims.Email)
					// Trust email verification from Google/Apple, but not Discord (emails can be unverified on Discord)
					if claims.EmailVerified != nil && *claims.EmailVerified && provider != "discord" {
						_ = svc.SetEmailVerified(c.Request.Context(), u.ID, true)
					}
					if strings.TrimSpace(provUsername) != "" {
						_ = svc.SetProviderUsername(c.Request.Context(), userID, issuer, claims.Subject, provUsername)
					}
				}
			}
			if !matched {
				displayName := ""
				if claims.Name != nil {
					displayName = *claims.Name
				}
				username := svc.DeriveUsernameForOAuth(c.Request.Context(), provider, provUsername, email, displayName)
				if u, err := svc.CreateUser(c.Request.Context(), email, username); err == nil {
					userID = u.ID
					// Trust email verification from Google/Apple, but not Discord (emails can be unverified on Discord)
					if claims.EmailVerified != nil && *claims.EmailVerified && provider != "discord" {
						_ = svc.SetEmailVerified(c.Request.Context(), u.ID, true)
					}
					_ = svc.LinkProviderByIssuer(c.Request.Context(), u.ID, issuer, provider, claims.Subject, claims.Email)
					if strings.TrimSpace(provUsername) != "" {
						_ = svc.SetProviderUsername(c.Request.Context(), u.ID, issuer, claims.Subject, provUsername)
					}
					created = true
				} else {
					ginutil.ServerErrWithLog(c, "user_creation_failed", err, "failed to create user from oidc callback")
					return
				}
			}
		}
		extra := map[string]any{"provider": provider}
		sid, rt, _, _ := svc.IssueRefreshSession(c.Request.Context(), userID, c.Request.UserAgent(), nil)
		extra["sid"] = sid
		token, exp, err := svc.IssueAccessToken(c.Request.Context(), userID, email, extra)
		if err != nil {
			ginutil.ServerErrWithLog(c, "token_issue_failed", err, "failed to issue access token for oidc callback")
			return
		}
		ua := c.Request.UserAgent()
		ip := c.ClientIP()
		uaPtr, ipPtr := &ua, &ip
		svc.LogLogin(c.Request.Context(), userID, "oidc_login", sid, ipPtr, uaPtr)
		if created {
			svc.SendWelcome(c.Request.Context(), userID)
		}

		// Popup mode: return tiny HTML that postMessages tokens to opener
		if sd.UI == "popup" {
			targetOrigin, ok := ginutil.OriginFromBaseURL(svc.Options().BaseURL)
			if !ok {
				ginutil.ServerErrWithLog(c, "invalid_base_url", nil, "BaseURL must be absolute (scheme://host) for popup auth flow")
				return
			}
			payload := map[string]any{
				"type":          "AUTHKIT_OIDC_RESULT",
				"access_token":  token,
				"refresh_token": rt,
				"expires_in":    int64(time.Until(exp).Seconds()),
				"provider":      provider,
				"nonce":         sd.PopupNonce,
			}
			b, _ := json.Marshal(payload)
			html := buildOIDCPopupHTML(b, targetOrigin)
			c.Header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
			c.Data(http.StatusOK, "text/html; charset=utf-8", html)
			return
		}
		// If caller requests JSON explicitly, return JSON (useful for tests/tools)
		if strings.EqualFold(c.Query("format"), "json") || strings.Contains(c.GetHeader("Accept"), "application/json") {
			c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int64(time.Until(exp).Seconds()), "refresh_token": rt, "user": gin.H{"id": userID, "email": email}})
			return
		}
		// Default: full-page redirect with URL fragment for SPA to hydrate tokens
		base := svc.Options().BaseURL
		if base == "" {
			base = "/"
		}
		// Preserve original state so SPA can correlate (optional)
		frag := "#access_token=" + token + "&refresh_token=" + rt + "&expires_in=" + fmt.Sprint(int64(time.Until(exp).Seconds())) + "&provider=" + provider + "&state=" + state
		// Redirect to /auth/callback (under BaseURL) with fragment payload
		target := strings.TrimRight(base, "/") + "/auth/callback" + frag
		c.Redirect(http.StatusFound, target)
	}
}

func buildOIDCPopupHTML(payloadJSON []byte, targetOrigin string) []byte {
	// Always JSON-encode strings we interpolate into JS to avoid injection.
	originJSON, _ := json.Marshal(targetOrigin)
	html := "<!doctype html><html><body><script>\n" +
		"try {\n" +
		"  var data = " + string(payloadJSON) + ";\n" +
		"  var targetOrigin = " + string(originJSON) + ";\n" +
		"  if (window.opener) { window.opener.postMessage(data, targetOrigin); }\n" +
		"} finally { window.close(); }\n" +
		"</script></body></html>"
	return []byte(html)
}
