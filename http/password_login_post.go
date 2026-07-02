package authhttp

import (
	"errors"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"strings"
	"time"

	pwhash "github.com/open-rails/authkit/password"
)

func (s *Service) handlePasswordLoginPOST(w http.ResponseWriter, r *http.Request) {
	// IP-only pre-check before we even parse the body (fast path).
	if s.rateLimited(w, r, RLPasswordLogin) {
		return
	}

	var req struct {
		Email    string `json:"email"`
		Login    string `json:"login"` // email or username
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	identifier := firstTrimmedNonEmpty(req.Email, req.Login)

	// Per-identifier check: prevents distributed brute-force against a single account
	// from many IPs, each spending their own per-IP budget.
	if s.rateLimitedByIdentifier(w, r, RLPasswordLogin, identifier) {
		return
	}
	if identifier == "" {
		badRequest(w, ErrInvalidRequest)
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
			var pendingPreferredLanguage string
			if pending, perr := s.svc.GetPendingPhoneRegistrationByPhone(r.Context(), identifier); perr == nil && pending != nil {
				hasPending = true
				pendingUsername = pending.Username
				pendingPasswordHash = pending.PasswordHash
				pendingPreferredLanguage = pending.PreferredLanguage
				if ok, verr := pwhash.VerifyArgon2id(pending.PasswordHash, req.Password); verr == nil && ok {
					passwordMatches = true
				}
			}
			recoveredUserID, recoveryErr, handled := recoverPendingPhoneLogin(
				hasPending,
				passwordMatches,
				s.svc.Options().RegistrationVerificationRequired(),
				func() error {
					_, createErr := s.svc.CreatePendingPhoneRegistrationWithLanguage(r.Context(), identifier, pendingUsername, pendingPasswordHash, pendingPreferredLanguage)
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
					if recoveryErr == ErrPhoneNotVerified.String() {
						writeVerificationRequired(w, identifier, "phone")
						return
					}
					if recoveryErr == ErrInvalidCredentials.String() {
						logLoginFailed(s, r, "", ErrInvalidCredentials.String())
					}
					unauthorized(w, ErrorCode(recoveryErr))
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
				unauthorized(w, ErrInvalidCredentials)
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
			unauthorized(w, ErrInvalidCredentials)
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
			if verr := s.svc.CheckUserPassword(r.Context(), userID, req.Password); verr != nil {
				if errors.Is(verr, authkit.ErrPasswordResetRequired) {
					logLoginFailed(s, r, userID, "password_reset_required")
					unauthorized(w, ErrPasswordResetRequired)
					return
				}
				logLoginFailed(s, r, userID, "invalid_credentials")
				unauthorized(w, ErrInvalidCredentials)
				return
			}

			if needsEmailVerify && s.svc.HasEmailSender() {
				if err := s.svc.RequestEmailVerification(r.Context(), *fetchedUser.Email, 0); err != nil {
					if s.handleDeliveryError(w, r, "password_login", "send_email_verification", err) {
						return
					}
					serverErr(w, ErrEmailVerificationFailed)
					return
				}
				logLoginFailed(s, r, userID, "email_not_verified")
				writeVerificationRequired(w, *fetchedUser.Email, "email")
				return
			}

			if needsPhoneVerify && s.svc.SMSAvailable() {
				if err := s.svc.SendPhoneVerificationToUser(r.Context(), *fetchedUser.PhoneNumber, userID, 0); err != nil {
					if s.handleDeliveryError(w, r, "password_login", "send_phone_verification", err) {
						return
					}
					serverErr(w, ErrPhoneVerificationFailed)
					return
				}
				logLoginFailed(s, r, userID, "phone_not_verified")
				writeVerificationRequired(w, *fetchedUser.PhoneNumber, "phone")
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
			if errors.Is(err, authkit.ErrUserBanned) {
				logLoginFailed(s, r, userID, "user_banned")
				unauthorized(w, ErrUserBanned)
				return
			}
			if errors.Is(err, authkit.ErrPasswordResetRequired) {
				logLoginFailed(s, r, userID, "password_reset_required")
				unauthorized(w, ErrPasswordResetRequired)
				return
			}
			logLoginFailed(s, r, userID, "invalid_credentials")
			unauthorized(w, ErrInvalidCredentials)
			return
		}
	} else {
		token, exp, err = s.svc.PasswordLogin(r.Context(), loginEmail, req.Password, nil)
		if err != nil {
			if errors.Is(err, authkit.ErrUserBanned) {
				logLoginFailed(s, r, "", "user_banned")
				unauthorized(w, ErrUserBanned)
				return
			}
			if errors.Is(err, authkit.ErrPasswordResetRequired) {
				logLoginFailed(s, r, "", "password_reset_required")
				unauthorized(w, ErrPasswordResetRequired)
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
					_, createErr := s.svc.CreatePendingRegistrationWithLanguage(r.Context(), loginEmail, pendingUser.Username, pendingUser.PasswordHash, 0, pendingUser.PreferredLanguage)
					return createErr
				},
				func() (string, time.Time, error) {
					return s.svc.PasswordLogin(r.Context(), loginEmail, req.Password, nil)
				},
			)
			if handled {
				if recoveryErr != "" {
					if recoveryErr == ErrEmailNotVerified.String() {
						writeVerificationRequired(w, loginEmail, "email")
						return
					}
					if recoveryErr == ErrInvalidCredentials.String() {
						logLoginFailed(s, r, "", ErrInvalidCredentials.String())
					}
					unauthorized(w, ErrorCode(recoveryErr))
					return
				}
				token, exp = recoveryToken, recoveryExp
			} else {
				logLoginFailed(s, r, "", "invalid_credentials")
				unauthorized(w, ErrInvalidCredentials)
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
		if twoFAErr == nil && twoFASettings != nil && twoFASettings.Enabled && s.svc.TwoFactorEnabled() {
			verificationID, method, factor, err := s.svc.Require2FAForLoginFactor(r.Context(), finalUserID, "")
			if err != nil {
				if s.handleDeliveryError(w, r, "password_login", "send_2fa_code", err) {
					return
				}
				serverErr(w, ErrTwoFASendFailed)
				return
			}
			challenge, err := s.svc.Create2FAChallenge(r.Context(), finalUserID)
			if err != nil {
				serverErr(w, ErrTwoFAChallengeFailed)
				return
			}
			obfuscatedID := obfuscateVerificationID(verificationID)
			factors := twoFactorFactorResponses(twoFASettings.Factors)
			writeJSON(w, http.StatusOK, map[string]any{
				"requires_2fa":    true,
				"user_id":         finalUserID,
				"method":          method,
				"verification_id": obfuscatedID,
				"challenge":       challenge,
				"default_factor": twoFactorFactorResponse{
					ID:          factor.ID,
					Method:      factor.Method,
					IsDefault:   factor.IsDefault,
					PhoneNumber: factor.PhoneNumber,
				},
				"available_factors": factors,
			})
			return
		}
		// Create the refresh session AND mint its access token from a single user
		// load + MFA read (#227) rather than IssueRefreshSession + IssueAccessToken,
		// which each re-read + re-gated the same row. The banned gate still fires with
		// ErrUserBanned; the ID-token email the old path fetched here was ignored by
		// IssueAccessToken, so it's gone.
		sid, rt, accessTok, accessExp, _, issueErr := s.svc.IssueAuthenticatedSession(r.Context(), finalUserID, r.UserAgent(), nil, []string{"pwd"}, nil)
		if issueErr != nil {
			if errors.Is(issueErr, authkit.ErrUserBanned) {
				logLoginFailed(s, r, finalUserID, "user_banned")
				unauthorized(w, ErrUserBanned)
				return
			}
			serverErr(w, ErrSessionCreationFailed)
			return
		}
		ua := r.UserAgent()
		ip := remoteIP(r)
		uaPtr, ipPtr := &ua, &ip
		s.svc.LogSessionCreated(r.Context(), finalUserID, "password_login", sid, ipPtr, uaPtr)
		writeAccessTokenJSON(w, http.StatusOK, newAuthTokens(accessTok, rt, accessExp), nil)
		return
	}

	// Distinct 3-field shape (no refresh_token) for the already-fresh re-issue path;
	// intentionally not the full token-pair envelope.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(exp).Seconds()),
	})
}

// writeVerificationRequired emits the structured "registration verification
// required" handoff, parallel to the requires_2fa response. By the time this is
// called the caller has already (re)sent a fresh verification code; the
// frontend routes the user to the OTP verify page using identifier + channel.
func writeVerificationRequired(w http.ResponseWriter, identifier, channel string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"requires_verification": true,
		"identifier":            identifier,
		"channel":               channel,
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
