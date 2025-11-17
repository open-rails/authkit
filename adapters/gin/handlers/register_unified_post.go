package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// E.164 phone number regex (basic validation)
var e164PhoneRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// HandleRegisterUnifiedPOST handles POST /auth/register
// Accepts either email or phone number in the identifier field
// Server disambiguates based on format
func HandleRegisterUnifiedPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type registerReq struct {
		Identifier string `json:"identifier"` // email or phone number
		Username   string `json:"username"`
		Password   string `json:"password"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthRegister) {
			ginutil.TooMany(c)
			return
		}

		var req registerReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		identifier := strings.TrimSpace(req.Identifier)
		username := strings.TrimSpace(req.Username)
		pass := req.Password

		if identifier == "" || username == "" || pwhash.Validate(pass) != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		if err := ginutil.ValidateUsername(username); err != nil {
			ginutil.BadRequest(c, err.Error())
			return
		}

		// Disambiguate: phone number vs email
		isPhone := e164PhoneRegex.MatchString(identifier)
		isEmail := strings.Contains(identifier, "@")

		if !isPhone && !isEmail {
			ginutil.BadRequest(c, "invalid_identifier")
			return
		}

		if isPhone && isEmail {
			// This shouldn't happen in practice, but handle edge case
			ginutil.BadRequest(c, "invalid_identifier")
			return
		}

		// Hash password
		phc, err := pwhash.HashArgon2id(pass)
		if err != nil {
			ginutil.ServerErrWithLog(c, "hash_failed", err, "failed to hash password during registration")
			return
		}

		if isPhone {
			// Phone registration requires SMS sender
			if !svc.HasSMSSender() {
				ginutil.ServerErrWithLog(c, "phone_registration_unavailable", nil, "sms sender not configured for phone registration")
				return
			}

			// Check if phone or username is taken
			phoneTaken, usernameTaken, err := svc.CheckPhoneRegistrationConflict(c.Request.Context(), identifier, username)
			if err != nil {
				ginutil.ServerErrWithLog(c, "database_error", err, "failed to check phone registration conflicts")
				return
			}
			if phoneTaken {
				ginutil.BadRequest(c, "phone_in_use")
				return
			}
			if usernameTaken {
				ginutil.BadRequest(c, "username_in_use")
				return
			}

			// Create pending phone registration and send SMS
			_, err = svc.CreatePendingPhoneRegistration(c.Request.Context(), identifier, username, phc)
			if err != nil {
				ginutil.ServerErrWithLog(c, "registration_failed", err, "failed to create pending phone registration")
				return
			}

			c.JSON(http.StatusAccepted, gin.H{
				"ok":      true,
				"message": "Registration pending. Please check your phone for a verification code.",
				"phone":   identifier,
			})
			return
		}

		// Email registration
		if !svc.HasEmailSender() {
			ginutil.ServerErrWithLog(c, "email_registration_unavailable", nil, "email sender not configured for email registration")
			return
		}

		// Check if email or username is taken (in users OR pending_registrations)
		emailTaken, usernameTaken, err := svc.CheckPendingRegistrationConflict(c.Request.Context(), identifier, username)
		if err != nil {
			ginutil.ServerErrWithLog(c, "database_error", err, "failed to check pending registration conflicts")
			return
		}
		if emailTaken {
			ginutil.BadRequest(c, "email_in_use")
			return
		}
		if usernameTaken {
			ginutil.BadRequest(c, "username_in_use")
			return
		}

		// Create pending registration (not a real user yet)
		_, err = svc.CreatePendingRegistration(c.Request.Context(), identifier, username, phc, 0)
		if err != nil {
			ginutil.ServerErrWithLog(c, "registration_failed", err, "failed to create pending email registration")
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"ok":      true,
			"message": "Registration pending. Please check your email to verify your account.",
			"email":   identifier,
		})
	}
}
