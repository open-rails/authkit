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
		Org      string `json:"org"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		badRequest(w, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Org) != "" && !strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "multi") {
		badRequest(w, "org_not_supported")
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
	requiresVerification := s.svc.Options().RegistrationVerificationRequired()

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
		// Fetch user by email so verification checks below can inspect email_verified.
		usr, e := s.svc.GetUserByEmail(r.Context(), loginEmail)
		if e == nil && usr != nil {
			fetchedUser = &userWithEmail{
				ID:            usr.ID,
				Email:         usr.Email,
				PhoneNumber:   usr.PhoneNumber,
				EmailVerified: usr.EmailVerified,
				PhoneVerified: usr.PhoneVerified,
				CreatedAt:     usr.CreatedAt,
			}
			userID = usr.ID
		}
	case strings.HasPrefix(identifier, "+"):
		usr, e := s.svc.GetUserByPhone(r.Context(), identifier)
		if e != nil || usr == nil {
			hasPending := false
			passwordMatches := false
			var pendingUsername string
			var pendingPasswordHash string
			if pending, perr := s.svc.GetPendingPhoneRegistrationByPhone(r.Context(), identifier); perr == nil && pending != nil {
				hasPending = true
				pendingUsername = pending.Username
				pendingPasswordHash = pending.PasswordHash
				if ok, verr := pwhash.VerifyArgon2id(pending.PasswordHash, req.Password); verr == nil && ok {
					passwordMatches = true
				}
			}
			recoveredUserID, recoveryErr, handled := recoverPendingPhoneLogin(
				hasPending,
				passwordMatches,
				s.svc.Options().RegistrationVerificationRequired(),
				func() error {
					_, createErr := s.svc.CreatePendingPhoneRegistration(r.Context(), identifier, pendingUsername, pendingPasswordHash)
					return createErr
				},
				func() (string, error) {
					usr, e = s.svc.GetUserByPhone(r.Context(), identifier)
					if e != nil || usr == nil {
						if e != nil {
							return "", e
						}
						return "", errors.New("user_not_found")
					}
					return usr.ID, nil
				},
			)
			if handled {
				if recoveryErr != "" {
					if recoveryErr == "invalid_credentials" {
						logLoginFailed(s, r, "", "invalid_credentials")
					}
					unauthorized(w, recoveryErr)
					return
				}
				userID = recoveredUserID
			}
			if userID != "" && usr != nil {
				fetchedUser = &userWithEmail{
					ID:            usr.ID,
					Email:         usr.Email,
					PhoneNumber:   usr.PhoneNumber,
					EmailVerified: usr.EmailVerified,
					PhoneVerified: usr.PhoneVerified,
					CreatedAt:     usr.CreatedAt,
				}
				if usr.Email != nil {
					loginEmail = *usr.Email
				}
			}
			if userID == "" {
				logLoginFailed(s, r, "", "invalid_credentials")
				unauthorized(w, "invalid_credentials")
				return
			}
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

	// Verify password BEFORE sending any OTP to prevent unauthenticated users
	// from triggering OTP sends (spam/cost abuse) or enumerating accounts.
	if requiresVerification && fetchedUser != nil && userID != "" {
		needsEmailVerify := !fetchedUser.EmailVerified && fetchedUser.Email != nil && fetchedUser.CreatedAt.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
		needsPhoneVerify := !fetchedUser.PhoneVerified && fetchedUser.PhoneNumber != nil && fetchedUser.CreatedAt.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

		if needsEmailVerify || needsPhoneVerify {
			if !s.svc.VerifyUserPassword(r.Context(), userID, req.Password) {
				logLoginFailed(s, r, userID, "invalid_credentials")
				unauthorized(w, "invalid_credentials")
				return
			}

			if needsEmailVerify && s.svc.HasEmailSender() {
				_ = s.svc.RequestEmailVerification(r.Context(), *fetchedUser.Email, 0)
				logLoginFailed(s, r, userID, "email_not_verified")
				unauthorized(w, "email_not_verified")
				return
			}

			if needsPhoneVerify && s.svc.HasSMSSender() {
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
			hasPending := pendingErr == nil && pendingUser != nil
			pendingPasswordMatches := false
			if hasPending {
				pendingPasswordMatches = s.svc.VerifyPendingPassword(r.Context(), loginEmail, req.Password)
			}
			recoveryToken, recoveryExp, recoveryErr, handled := recoverPendingEmailLogin(
				hasPending,
				pendingPasswordMatches,
				s.svc.Options().RegistrationVerificationRequired(),
				func() error {
					_, createErr := s.svc.CreatePendingRegistration(r.Context(), loginEmail, pendingUser.Username, pendingUser.PasswordHash, 0)
					return createErr
				},
				func() (string, time.Time, error) {
					return s.svc.PasswordLogin(r.Context(), loginEmail, req.Password, nil)
				},
			)
			if handled {
				if recoveryErr != "" {
					if recoveryErr == "invalid_credentials" {
						logLoginFailed(s, r, "", "invalid_credentials")
					}
					unauthorized(w, recoveryErr)
					return
				}
				token, exp = recoveryToken, recoveryExp
			} else {
				logLoginFailed(s, r, "", "invalid_credentials")
				unauthorized(w, "invalid_credentials")
				return
			}
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
		if strings.TrimSpace(req.Org) != "" && strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "multi") {
			token, exp, err = s.svc.IssueOrgAccessToken(r.Context(), finalUserID, emailForToken, req.Org, map[string]any{"sid": sid})
			if err != nil {
				if errors.Is(err, core.ErrNotOrgMember) {
					forbidden(w, "not_org_member")
					return
				}
				if errors.Is(err, core.ErrOrgNotFound) {
					notFound(w, "org_not_found")
					return
				}
				serverErr(w, "token_issue_failed")
				return
			}
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

func recoverPendingEmailLogin(
	hasPending bool,
	passwordMatches bool,
	requireVerifiedRegistrations bool,
	createPending func() error,
	retryPasswordLogin func() (string, time.Time, error),
) (token string, exp time.Time, responseErr string, handled bool) {
	if !hasPending || !passwordMatches {
		return "", time.Time{}, "", false
	}
	if err := createPending(); err != nil {
		return "", time.Time{}, "invalid_credentials", true
	}
	if requireVerifiedRegistrations {
		return "", time.Time{}, "email_not_verified", true
	}
	token, exp, err := retryPasswordLogin()
	if err != nil {
		return "", time.Time{}, "invalid_credentials", true
	}
	return token, exp, "", true
}

func recoverPendingPhoneLogin(
	hasPending bool,
	passwordMatches bool,
	requireVerifiedRegistrations bool,
	createPending func() error,
	loadUserByPhone func() (string, error),
) (userID string, responseErr string, handled bool) {
	if !hasPending || !passwordMatches {
		return "", "", false
	}
	if err := createPending(); err != nil {
		return "", "invalid_credentials", true
	}
	if requireVerifiedRegistrations {
		return "", "phone_not_verified", true
	}
	userID, err := loadUserByPhone()
	if err != nil || strings.TrimSpace(userID) == "" {
		return "", "invalid_credentials", true
	}
	return userID, "", true
}
