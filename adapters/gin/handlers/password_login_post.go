package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// HandlePasswordLoginPOST handles POST /auth/password/login
func HandlePasswordLoginPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type loginReq struct {
		Email    string `json:"email"`
		Login    string `json:"login"` // email or username
		Password string `json:"password"`
	}
	type userWithEmail struct {
		ID            string
		Email         *string
		PhoneNumber   *string
		EmailVerified bool
		PhoneVerified bool
		CreatedAt     time.Time
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordLogin) {
			ginutil.TooMany(c)
			return
		}
		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		identifier := strings.TrimSpace(req.Email)
		if identifier == "" {
			identifier = strings.TrimSpace(req.Login)
		}
		if identifier == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Determine if identifier is email, phone, or username and get user ID
		var loginEmail string
		var userID string
		var fetchedUser *userWithEmail

		if strings.Contains(identifier, "@") {
			// Email-based login
			loginEmail = identifier
		} else if strings.HasPrefix(identifier, "+") {
			// Phone-based login (E.164 format starts with +)
			usr, e := svc.GetUserByPhone(c.Request.Context(), identifier)
			if e != nil || usr == nil {
				// Check if this is a pending phone registration with correct password
				if pending, perr := svc.GetPendingPhoneRegistrationByPhone(c.Request.Context(), identifier); perr == nil && pending != nil {
					if ok, verr := pwhash.VerifyArgon2id(pending.PasswordHash, req.Password); verr == nil && ok {
						// Recreate pending to generate and send a fresh code via SMS
						_, _ = svc.CreatePendingPhoneRegistration(c.Request.Context(), identifier, pending.Username, pending.PasswordHash)
						ginutil.Unauthorized(c, "phone_not_verified")
						return
					}
				}
				ginutil.Unauthorized(c, "invalid_credentials")
				return
			}
			fetchedUser = &userWithEmail{
				ID:            usr.ID,
				Email:         usr.Email,
				PhoneNumber:   usr.PhoneNumber,
				EmailVerified: usr.EmailVerified,
				PhoneVerified: usr.PhoneVerified,
				CreatedAt:     usr.CreatedAt,
			}
			userID = usr.ID
			if usr.Email != nil {
				loginEmail = *usr.Email
			}
		} else {
			// Username-based login
			usr, e := svc.GetUserByUsername(c.Request.Context(), identifier)
			if e != nil || usr == nil {
				ginutil.Unauthorized(c, "invalid_credentials")
				return
			}
			fetchedUser = &userWithEmail{
				ID:            usr.ID,
				Email:         usr.Email,
				PhoneNumber:   usr.PhoneNumber,
				EmailVerified: usr.EmailVerified,
				PhoneVerified: usr.PhoneVerified,
				CreatedAt:     usr.CreatedAt,
			}
			userID = usr.ID
			if usr.Email != nil {
				loginEmail = *usr.Email
			}
		}

		// For phone/username login, we already have userID
		// For email login, we validate via PasswordLogin which will look it up

		// Require email verification for password-based registrations created after 2025-01-01
		// Only check this for email-based registrations (not phone)
		if fetchedUser != nil && !fetchedUser.EmailVerified && fetchedUser.Email != nil && fetchedUser.CreatedAt.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
			// Check if user has a password (password-based registration vs OAuth/OIDC)
			if svc.HasPassword(c.Request.Context(), userID) {
				// If no email sender configured, this is a misconfiguration - allow login
				if !svc.HasEmailSender() {
					// User is stuck: can't verify email, but we'll let them in
					// This shouldn't happen if registration properly checks for email sender
				} else {
					// Send verification email automatically when user tries to login with unverified email and they cannot register again.
					_ = svc.RequestEmailVerification(c.Request.Context(), *fetchedUser.Email, 0)
					ginutil.Unauthorized(c, "email_not_verified")
					return
				}
			}
		}

		// Require phone verification for password-based registrations created after 2025-01-01
		// Only check this for phone-based registrations (not email)
		if fetchedUser != nil && !fetchedUser.PhoneVerified && fetchedUser.PhoneNumber != nil && fetchedUser.CreatedAt.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
			// Check if user has a password (password-based registration vs OAuth/OIDC)
			if svc.HasPassword(c.Request.Context(), userID) {
				// If no SMS sender configured, this is a misconfiguration - allow login
				if !svc.HasSMSSender() {
					// User is stuck: can't verify phone, but we'll let them in
					// This shouldn't happen if registration properly checks for SMS sender
				} else {
					// Send verification SMS automatically when user tries to login with unverified phone
					_ = svc.SendPhoneVerificationToUser(c.Request.Context(), *fetchedUser.PhoneNumber, userID, 0)
					ginutil.Unauthorized(c, "phone_not_verified")
					return
				}
			}
		}

		var (
			token string
			exp   time.Time
			err   error
		)
		if userID != "" {
			// Phone or username flow: verify by user ID (email may be NULL)
			token, exp, err = svc.PasswordLoginByUserID(c.Request.Context(), userID, req.Password, nil)
			if err != nil {
				ginutil.Unauthorized(c, "invalid_credentials")
				return
			}
		} else {
			// Email flow: verify by email
			token, exp, err = svc.PasswordLogin(c.Request.Context(), loginEmail, req.Password, nil)
			if err != nil {
				// If PasswordLogin failed, check if user is in pending_registrations (unverified)
				pendingUser, pendingErr := svc.GetPendingRegistrationByEmail(c.Request.Context(), loginEmail)
				if pendingErr == nil && pendingUser != nil {
					// User exists in pending_registrations - verify password
					if svc.VerifyPendingPassword(c.Request.Context(), loginEmail, req.Password) {
						// Password is correct but email not verified - resend verification email
						// Resend by creating new pending registration with same credentials (generates new code)
						_, _ = svc.CreatePendingRegistration(c.Request.Context(), loginEmail, pendingUser.Username, pendingUser.PasswordHash, 0)
						ginutil.Unauthorized(c, "email_not_verified")
						return
					}
				}
				// Either user doesn't exist, or password is wrong
				ginutil.Unauthorized(c, "invalid_credentials")
				return
			}
		}

		// Get fresh user info for session creation
		var finalUserID string
		if userID != "" {
			finalUserID = userID
		} else {
			// Email-based login - look up user to get ID
			usr, _ := svc.GetUserByEmail(c.Request.Context(), loginEmail)
			if usr != nil {
				finalUserID = usr.ID
			}
		}

		if finalUserID != "" {
			// Check if user has 2FA enabled
			twoFASettings, twoFAErr := svc.Get2FASettings(c.Request.Context(), finalUserID)
			if twoFAErr == nil && twoFASettings != nil && twoFASettings.Enabled {
				// 2FA is enabled - send verification code and require 2FA
				verificationID, err := svc.Require2FAForLogin(c.Request.Context(), finalUserID)
				if err != nil {
					ginutil.ServerErrWithLog(c, "2fa_send_failed", err, "failed to send 2fa verification")
					return
				}
				// Return response indicating 2FA is required
				c.JSON(http.StatusOK, gin.H{
					"requires_2fa":    true,
					"user_id":         finalUserID,
					"method":          twoFASettings.Method,
					"verification_id": verificationID,
				})
				return
			}

			// No 2FA or 2FA not enabled - proceed with normal login
			sid, rt, _, _ := svc.IssueRefreshSession(c.Request.Context(), finalUserID, c.Request.UserAgent(), nil)
			ua := c.Request.UserAgent()
			ip := c.ClientIP()
			uaPtr, ipPtr := &ua, &ip
			svc.LogLogin(c.Request.Context(), finalUserID, "password_login", sid, ipPtr, uaPtr)

			emailForToken := ""
			if fetchedUser != nil && fetchedUser.Email != nil {
				emailForToken = *fetchedUser.Email
			} else {
				// For email-based login, fetch the user
				usr, _ := svc.GetUserByEmail(c.Request.Context(), loginEmail)
				if usr != nil && usr.Email != nil {
					emailForToken = *usr.Email
				}
			}
			if t2, e2, e := svc.IssueAccessToken(c.Request.Context(), finalUserID, emailForToken, map[string]any{"sid": sid}); e == nil {
				token, exp = t2, e2
			}
			c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int64(time.Until(exp).Seconds()), "refresh_token": rt})
			return
		}
		c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int64(time.Until(exp).Seconds())})
	}
}
