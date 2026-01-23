package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type discordTokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Global   string `json:"global_name"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

// HandleDiscordCallbackGET completes the Discord OAuth2 code flow and issues our tokens.
func HandleDiscordCallbackGET(cfg OIDCConfig, svc core.Provider, rl ginutil.RateLimiter, site string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Track site name if present in context

		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "site", site))

		logFailed := func(userID string) {
			ua := c.Request.UserAgent()
			ip := c.ClientIP()
			uaPtr, ipPtr := &ua, &ip
			ctx := c.Request.Context()
			ctx = context.WithValue(ctx, "login_success", false)
			svc.LogLogin(ctx, userID, "oauth_login:discord", "", ipPtr, uaPtr)
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLOIDCCallback) {

			ginutil.TooMany(c)
			return
		}
		if qErr := c.Query("error"); qErr != "" {

			ginutil.BadRequest(c, qErr)
			return
		}
		state := c.Query("state")
		code := c.Query("code")
		if state == "" || code == "" {

			ginutil.BadRequest(c, "invalid_request")
			return
		}
		sd, ok, err := cfg.StateCache.Get(c.Request.Context(), state)
		_ = cfg.StateCache.Del(c.Request.Context(), state)
		if err != nil || !ok || sd.Provider != "discord" {

			ginutil.BadRequest(c, "invalid_state")
			return
		}

		// Exchange code for token
		rp, ok := cfg.Manager.Provider("discord")
		if !ok || strings.TrimSpace(rp.ClientID) == "" || strings.TrimSpace(rp.ClientSecret) == "" {
			ginutil.BadRequest(c, "unknown_provider")
			return
		}
		form := url.Values{}
		form.Set("client_id", rp.ClientID)
		form.Set("client_secret", rp.ClientSecret)
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", sd.RedirectURI)
		req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, "https://discord.com/api/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {

			ginutil.Unauthorized(c, "exchange_failed")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			log.Println("Discord token exchange failed with status:", resp.StatusCode, "body:", string(body))
			ginutil.Unauthorized(c, "exchange_failed")
			return
		}
		body, _ := io.ReadAll(resp.Body)
		var tok discordTokenResp
		if json.Unmarshal(body, &tok) != nil || strings.TrimSpace(tok.AccessToken) == "" {

			ginutil.Unauthorized(c, "exchange_failed")
			return
		}

		// Fetch user info
		ureq, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, "https://discord.com/api/users/@me", nil)
		ureq.Header.Set("Authorization", tok.TokenType+" "+tok.AccessToken)
		uresp, err := http.DefaultClient.Do(ureq)
		if err != nil {

			ginutil.Unauthorized(c, "userinfo_failed")
			return
		}
		defer uresp.Body.Close()
		if uresp.StatusCode != 200 {

			ginutil.Unauthorized(c, "userinfo_failed")
			return
		}
		ubody, _ := io.ReadAll(uresp.Body)
		var du discordUser
		if json.Unmarshal(ubody, &du) != nil || strings.TrimSpace(du.ID) == "" {

			ginutil.Unauthorized(c, "userinfo_failed")
			return
		}

		// Build email and preferred username
		// Only use email if it's verified by Discord
		email := ""
		if du.Verified && strings.TrimSpace(du.Email) != "" {
			email = strings.TrimSpace(du.Email)
		}
		preferred := du.Username
		display := du.Global

		// Account linking/creation mirrors OIDC path but uses issuer = "https://discord.com"
		const issuer = "https://discord.com"
		var userID string
		created := false

		// If link flow was initiated, bind this Discord account to the requesting user
		if sd.LinkUserID != "" {
			// Prevent linking if this Discord account is already linked to another user
			if uid0, _, err := svc.GetProviderLinkByIssuer(c.Request.Context(), issuer, du.ID); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
				logFailed(sd.LinkUserID)
				ginutil.BadRequest(c, "provider_already_linked")
				return
			}
			userID = sd.LinkUserID
			// Only store email_at_provider if verified (email is empty if not verified)
			_ = svc.LinkProviderByIssuer(c.Request.Context(), userID, issuer, "discord", du.ID, strptr(email))
			if strings.TrimSpace(preferred) != "" {
				_ = svc.SetProviderUsername(c.Request.Context(), userID, issuer, du.ID, preferred)
			}
		} else if uid, _, err := svc.GetProviderLinkByIssuer(c.Request.Context(), issuer, du.ID); err == nil && uid != "" {
			userID = uid
		} else if email != "" {
			// Only match by email if it's verified on Discord (email will be empty if not verified)
			if u, err := svc.GetUserByEmail(c.Request.Context(), email); err == nil && u != nil {
				userID = u.ID
				_ = svc.LinkProviderByIssuer(c.Request.Context(), u.ID, issuer, "discord", du.ID, strptr(email))
				// Trust Discord's email verification - mark as verified even if it wasn't before
				_ = svc.SetEmailVerified(c.Request.Context(), u.ID, true)
				_ = svc.SetProviderUsername(c.Request.Context(), u.ID, issuer, du.ID, preferred)
			}
		}
		if userID == "" {
			username := svc.DeriveUsernameForOAuth(c.Request.Context(), "discord", preferred, email, display)
			if u, err := svc.CreateUser(c.Request.Context(), email, username); err == nil && u != nil {
				userID = u.ID
				_ = svc.LinkProviderByIssuer(c.Request.Context(), u.ID, issuer, "discord", du.ID, strptr(email))
				// Email is already verified if we got here (checked above)
				if email != "" {
					_ = svc.SetEmailVerified(c.Request.Context(), u.ID, true)
				}
				_ = svc.SetProviderUsername(c.Request.Context(), u.ID, issuer, du.ID, preferred)
				created = true
			} else {
				ginutil.ServerErrWithLog(c, "user_creation_failed", err, "failed to create user from discord oauth")
				return
			}
		}

		// Issue sessions + tokens
		extra := map[string]any{"provider": "discord"}
		sid, rt, _, err := svc.IssueRefreshSession(c.Request.Context(), userID, c.Request.UserAgent(), nil)
		if err != nil {
			logFailed(userID)
			if errors.Is(err, core.ErrUserBanned) {
				ginutil.Unauthorized(c, "user_banned")
				return
			}
			ginutil.ServerErrWithLog(c, "session_issue_failed", err, "failed to issue refresh session for discord oauth")
			return
		}
		extra["sid"] = sid
		accessToken, exp, err := svc.IssueAccessToken(c.Request.Context(), userID, email, extra)
		if err != nil {
			logFailed(userID)
			if errors.Is(err, core.ErrUserBanned) {
				ginutil.Unauthorized(c, "user_banned")
				return
			}
			ginutil.ServerErrWithLog(c, "token_issue_failed", err, "failed to issue token for discord oauth")
			return
		}
		ua := c.Request.UserAgent()
		ip := c.ClientIP()
		uaPtr, ipPtr := &ua, &ip
		svc.LogLogin(c.Request.Context(), userID, "oauth_login:discord", sid, ipPtr, uaPtr)
		if created {
			svc.SendWelcome(c.Request.Context(), userID)
		}
		if sd.UI == "popup" {
			targetOrigin, ok := ginutil.OriginFromBaseURL(svc.Options().BaseURL)
			if !ok {
				ginutil.ServerErrWithLog(c, "invalid_base_url", nil, "BaseURL must be absolute (scheme://host) for popup auth flow")
				return
			}
			payload := map[string]any{
				"type":          "AUTHKIT_OIDC_RESULT",
				"access_token":  accessToken,
				"refresh_token": rt,
				"expires_in":    int64(time.Until(exp).Seconds()),
				"provider":      "discord",
				"nonce":         sd.PopupNonce,
			}
			b, _ := json.Marshal(payload)
			html := buildOAuthPopupHTML(b, targetOrigin)
			c.Header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
			c.Data(http.StatusOK, "text/html; charset=utf-8", html)
			return
		}
		if strings.EqualFold(c.Query("format"), "json") || strings.Contains(c.GetHeader("Accept"), "application/json") {
			c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "token_type": "Bearer", "expires_in": int64(time.Until(exp).Seconds()), "refresh_token": rt, "user": gin.H{"id": userID, "email": email}})
			return
		}
		base := svc.Options().BaseURL
		if base == "" {
			base = "/"
		}
		frag := "#access_token=" + accessToken + "&refresh_token=" + rt + "&expires_in=" + fmt.Sprint(int64(time.Until(exp).Seconds())) + "&provider=discord&state=" + state
		target := strings.TrimRight(base, "/") + "/auth/callback" + frag
		c.Redirect(http.StatusFound, target)
	}
}

func buildOAuthPopupHTML(payloadJSON []byte, targetOrigin string) []byte {
	originJSON, _ := json.Marshal(targetOrigin)
	html := "<!doctype html><html><body><script>\n" +
		"try {\n" +
		"  var data = " + string(payloadJSON) + ";\n" +
		"  var targetOrigin = " + string(originJSON) + ";\n" +
		"  if (window.opener) { window.opener.postMessage(data, targetOrigin); }\n" +
		"} finally {  /*window.close();*/ }\n" +
		"</script></body></html>"
	return []byte(html)
}

func strptr(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	v := s
	return &v
}
