package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
	pwhash "github.com/open-rails/authkit/password"
)

func (s *Service) handlePasswordLoginPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLPasswordLogin) {
		tooMany(w)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Login    string `json:"login"` // email or username
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		badRequest(w, "invalid_request")
		return
	}

	identifier := strings.TrimSpace(req.Email)
	if identifier == "" {
		identifier = strings.TrimSpace(req.Login)
	}
	if identifier == "" {
		badRequest(w, "invalid_request")
		return
	}

	type userWithEmail struct {
		ID            string
		Email         *string
		PhoneNumber   *string
		EmailVerified bool
		PhoneVerified bool
		CreatedAt     time.Time
	}

	var loginEmail string
	var userID string
	var fetchedUser *userWithEmail

	switch {
	case strings.Contains(identifier, "@"):
		loginEmail = identifier
	case strings.HasPrefix(identifier, "+"):
		usr, e := s.svc.GetUserByPhone(r.Context(), identifier)
		if e != nil || usr == nil {
			if pending, perr := s.svc.GetPendingPhoneRegistrationByPhone(r.Context(), identifier); perr == nil && pending != nil {
				if ok, verr := pwhash.VerifyArgon2id(pending.PasswordHash, req.Password); verr == nil && ok {
					_, _ = s.svc.CreatePendingPhoneRegistration(r.Context(), identifier, pending.Username, pending.PasswordHash)
					unauthorized(w, "phone_not_verified")
					return
				}
			}
			logLoginFailed(s, r, "", "invalid_credentials")
			unauthorized(w, "invalid_credentials")
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
	default:
		usr, e := s.svc.GetUserByUsername(r.Context(), identifier)
		if e != nil || usr == nil {
			logLoginFailed(s, r, "", "invalid_credentials")
			unauthorized(w, "invalid_credentials")
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

	if fetchedUser != nil && !fetchedUser.EmailVerified && fetchedUser.Email != nil && fetchedUser.CreatedAt.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		if s.svc.HasPassword(r.Context(), userID) {
			if s.svc.HasEmailSender() {
				_ = s.svc.RequestEmailVerification(r.Context(), *fetchedUser.Email, 0)
				logLoginFailed(s, r, userID, "email_not_verified")
				unauthorized(w, "email_not_verified")
				return
			}
		}
	}

	if fetchedUser != nil && !fetchedUser.PhoneVerified && fetchedUser.PhoneNumber != nil && fetchedUser.CreatedAt.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		if s.svc.HasPassword(r.Context(), userID) {
			if s.svc.HasSMSSender() {
				_ = s.svc.SendPhoneVerificationToUser(r.Context(), *fetchedUser.PhoneNumber, userID, 0)
				logLoginFailed(s, r, userID, "phone_not_verified")
				unauthorized(w, "phone_not_verified")
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
		token, exp, err = s.svc.PasswordLoginByUserID(r.Context(), userID, req.Password, nil)
		if err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				logLoginFailed(s, r, userID, "user_banned")
				unauthorized(w, "user_banned")
				return
			}
			logLoginFailed(s, r, userID, "invalid_credentials")
			unauthorized(w, "invalid_credentials")
			return
		}
	} else {
		token, exp, err = s.svc.PasswordLogin(r.Context(), loginEmail, req.Password, nil)
		if err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				logLoginFailed(s, r, "", "user_banned")
				unauthorized(w, "user_banned")
				return
			}
			pendingUser, pendingErr := s.svc.GetPendingRegistrationByEmail(r.Context(), loginEmail)
			if pendingErr == nil && pendingUser != nil {
				if s.svc.VerifyPendingPassword(r.Context(), loginEmail, req.Password) {
					_, _ = s.svc.CreatePendingRegistration(r.Context(), loginEmail, pendingUser.Username, pendingUser.PasswordHash, 0)
					unauthorized(w, "email_not_verified")
					return
				}
			}
			logLoginFailed(s, r, "", "invalid_credentials")
			unauthorized(w, "invalid_credentials")
			return
		}
	}

	var finalUserID string
	if userID != "" {
		finalUserID = userID
	} else {
		usr, _ := s.svc.GetUserByEmail(r.Context(), loginEmail)
		if usr != nil {
			finalUserID = usr.ID
		}
	}

	if finalUserID != "" {
		twoFASettings, twoFAErr := s.svc.Get2FASettings(r.Context(), finalUserID)
		if twoFAErr == nil && twoFASettings != nil && twoFASettings.Enabled {
			verificationID, err := s.svc.Require2FAForLogin(r.Context(), finalUserID)
			if err != nil {
				serverErr(w, "2fa_send_failed")
				return
			}
			challenge, err := s.svc.Create2FAChallenge(r.Context(), finalUserID)
			if err != nil {
				serverErr(w, "2fa_challenge_failed")
				return
			}
			obfuscatedID := verificationID
			if len(verificationID) > 5 {
				obfuscatedID = strings.Repeat("*", len(verificationID)-5) + verificationID[len(verificationID)-5:]
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"requires_2fa":    true,
				"user_id":         finalUserID,
				"method":          twoFASettings.Method,
				"verification_id": obfuscatedID,
				"challenge":       challenge,
			})
			return
		}

		sid, rt, _, err := s.svc.IssueRefreshSession(r.Context(), finalUserID, r.UserAgent(), nil)
		if err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				logLoginFailed(s, r, finalUserID, "user_banned")
				unauthorized(w, "user_banned")
				return
			}
			serverErr(w, "session_creation_failed")
			return
		}
		ua := r.UserAgent()
		ip := clientIP(r)
		uaPtr, ipPtr := &ua, &ip
		s.svc.LogSessionCreated(r.Context(), finalUserID, "password_login", sid, ipPtr, uaPtr)

		emailForToken := ""
		if fetchedUser != nil && fetchedUser.Email != nil {
			emailForToken = *fetchedUser.Email
		} else {
			usr, _ := s.svc.GetUserByEmail(r.Context(), loginEmail)
			if usr != nil && usr.Email != nil {
				emailForToken = *usr.Email
			}
		}
		token, exp, err = s.svc.IssueAccessToken(r.Context(), finalUserID, emailForToken, map[string]any{"sid": sid})
		if err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				logLoginFailed(s, r, finalUserID, "user_banned")
				unauthorized(w, "user_banned")
				return
			}
			serverErr(w, "token_issue_failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  token,
			"token_type":    "Bearer",
			"expires_in":    int64(time.Until(exp).Seconds()),
			"refresh_token": rt,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(exp).Seconds()),
	})
}
