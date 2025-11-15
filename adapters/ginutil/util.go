package ginutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// RateLimiter is a minimal interface used by adapters.
type RateLimiter interface {
	AllowNamed(bucket string, key string) (bool, error)
}

// Bucket names used by authkit endpoints.
const (
	RLAuthToken                  = "auth_token"
	RLAuthRegister               = "auth_register"
	RLAuthRegisterResendEmail    = "auth_register_resend_email"
	RLAuthRegisterResendPhone    = "auth_register_resend_phone"
	RLAuthLogout                 = "auth_logout"
	RLAuthSessionsCurrent        = "auth_sessions_current"
	RLAuthSessionsList           = "auth_sessions_list"
	RLAuthSessionsRevoke         = "auth_sessions_revoke"
	RLAuthSessionsRevokeAll      = "auth_sessions_revoke_all"
	RLOIDCStart                  = "auth_oidc_start"
	RLOIDCCallback               = "auth_oidc_callback"
	RLPasswordLogin              = "auth_password_login"
	RLPasswordResetRequest       = "auth_pwd_reset_request"
	RLPasswordResetConfirm       = "auth_pwd_reset_confirm"
	RLEmailVerifyRequest         = "auth_email_verify_request"
	RLEmailVerifyConfirm         = "auth_email_verify_confirm"
	RLUserMe                     = "auth_user_me"
	RLUserUpdateUsername         = "auth_user_update_username"
	RLUserUpdateEmail            = "auth_user_update_email"
	RLUserEmailChangeRequest     = "auth_user_email_change_request"
	RLUserEmailChangeConfirm     = "auth_user_email_change_confirm"
	RLUserEmailChangeResend      = "auth_user_email_change_resend"
	RLUserDelete                 = "auth_user_delete"
	RLUserUnlinkProvider         = "auth_user_unlink_provider"
	RLUserPasswordChange         = "auth_user_password_change"
	RLAdminRolesGrant            = "auth_admin_roles_grant"
	RLAdminRolesRevoke           = "auth_admin_roles_revoke"
	RLAdminUserSessionsList      = "auth_admin_user_sessions_list"
	RLAdminUserSessionsRevoke    = "auth_admin_user_sessions_revoke"
	RLAdminUserSessionsRevokeAll = "auth_admin_user_sessions_revoke_all"
)

// AllowNamed applies a per-IP limit using the provided bucket name.
// It fails open on limiter error.
func AllowNamed(c *gin.Context, rl RateLimiter, bucket string) bool {
	if rl == nil {
		return true
	}
	ip := c.ClientIP()
	key := "auth:" + bucket + ":ip:" + ip
	ok, err := rl.AllowNamed(bucket, key)
	if err != nil {
		return true
	}
	return ok
}

// Error helpers
func SendErr(c *gin.Context, status int, code string) {
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}
func BadRequest(c *gin.Context, code string)   { SendErr(c, http.StatusBadRequest, code) }
func Unauthorized(c *gin.Context, code string) { SendErr(c, http.StatusUnauthorized, code) }
func Forbidden(c *gin.Context, code string)    { SendErr(c, http.StatusForbidden, code) }
func TooMany(c *gin.Context)                   { SendErr(c, http.StatusTooManyRequests, "rate_limited") }
func ServerErr(c *gin.Context, code string)    { SendErr(c, http.StatusInternalServerError, code) }
func NotFound(c *gin.Context, code string)     { SendErr(c, http.StatusNotFound, code) }

// ServerErrWithLog logs the underlying error/context before responding with a generic server error.
func ServerErrWithLog(c *gin.Context, code string, err error, message string) {
	entry := log.WithContext(c.Request.Context()).WithFields(log.Fields{
		"code":   code,
		"path":   c.FullPath(),
		"method": c.Request.Method,
	})
	if err != nil {
		entry = entry.WithError(err)
	}
	if strings.TrimSpace(message) == "" {
		message = "authkit server error"
	}
	entry.Error(message)
	ServerErr(c, code)
}

// RandB64 returns a URL-safe random string of length n bytes.
func RandB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// BuildRedirectURI constructs absolute redirect_uri based on request and provider.
func BuildRedirectURI(c *gin.Context, provider string) string {
	// Determine scheme/host considering reverse proxies
	scheme := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")
	if scheme == "" {
		if c.Request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = c.Request.Host
	}

	// Prefer deriving the callback path from the current request path so it
	// automatically includes any router group prefix (e.g., /api/v1).
	// Examples:
	//   GET  /api/v1/auth/oidc/google/login       -> /api/v1/auth/oidc/google/callback
	//   POST /api/v1/auth/oidc/google/link/start  -> /api/v1/auth/oidc/google/callback
	p := c.Request.URL.Path
	switch {
	case strings.HasSuffix(p, "/login"):
		p = strings.TrimSuffix(p, "/login") + "/callback"
	case strings.HasSuffix(p, "/link/start"):
		p = strings.TrimSuffix(p, "/link/start") + "/callback"
	default:
		// Fallback: use route pattern to capture any mounted prefix, then rebuild
		// the expected callback path.
		if fp := c.FullPath(); fp != "" {
			if i := strings.Index(fp, "/auth/oidc/"); i >= 0 {
				prefix := fp[:i]
				p = prefix + "/auth/oidc/" + provider + "/callback"
			} else {
				p = "/auth/oidc/" + provider + "/callback"
			}
		} else {
			p = "/auth/oidc/" + provider + "/callback"
		}
	}
	return scheme + "://" + host + p
}

// BearerToken extracts a Bearer token from an Authorization header value.
func BearerToken(authorization string) string {
	if authorization == "" {
		return ""
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// ParseIP parses string into net.IP (nil if empty).
func ParseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// ValidateUsername validates username according to the rules:
// - 4-30 characters
// - letters, numbers, and underscores only
// - must start with a letter
// - cannot contain @ or start with +
// - cannot be 'admin' or 'moderator'
func ValidateUsername(username string) error {
	username = strings.TrimSpace(username)

	if len(username) < 4 {
		return fmt.Errorf("username_too_short")
	}
	if len(username) > 30 {
		return fmt.Errorf("username_too_long")
	}

	if len(username) > 0 && (username[0] < 'a' || username[0] > 'z') && (username[0] < 'A' || username[0] > 'Z') {
		return fmt.Errorf("username_must_start_with_letter")
	}

	// Check for @ symbol (email-like)
	if strings.Contains(username, "@") {
		return fmt.Errorf("username_cannot_contain_at")
	}

	// Check for + at start (phone-like)
	if strings.HasPrefix(username, "+") {
		return fmt.Errorf("username_cannot_start_with_plus")
	}

	validPattern := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validPattern.MatchString(username) {
		return fmt.Errorf("username_invalid_characters")
	}

	lowerUsername := strings.ToLower(username)
	if lowerUsername == "admin" || lowerUsername == "moderator" {
		return fmt.Errorf("username_reserved")
	}

	return nil
}
