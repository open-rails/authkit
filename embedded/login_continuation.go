package embedded

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// loginProof is server-owned first-factor provenance. One current record per
// account bounds state; the nonce and exact-value claim distinguish issuances.
type loginProof struct {
	DeletionID      string `json:"deletion_id,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	ProviderIssuer  string `json:"provider_issuer,omitempty"`
	ProviderID      string `json:"provider_id,omitempty"`
	ProviderSubject string `json:"provider_subject,omitempty"`
	PasskeyID       string `json:"passkey_id,omitempty"`
	nonce           string
	ReturnTo        string            `json:"return_to,omitempty"`
	Input           LoginSessionInput `json:"input"`
	Version         int64             `json:"version"`
	Issuer          string            `json:"issuer"`
	AuthenticatedAt time.Time         `json:"authenticated_at"`
	NonceHash       string            `json:"nonce_hash"`
	Enrollment      bool              `json:"enrollment"`
	expected        []byte
}

// LoginChallengeInput supplies the second proof; clients never supply AMR or
// first-factor provenance. Backup codes are independently stored recovery keys.
type LoginChallengeInput struct {
	UserID     string
	Challenge  string
	FactorID   string
	Code       string
	BackupCode bool
	UserAgent  string
	IP         string
}

func (s *engine) loadLoginProof(ctx context.Context, userID, nonce string) (loginProof, error) {
	var proof loginProof
	raw, ok, err := s.ephemReadJSON(ctx, keyTwoFactorChallenge+userID, &proof)
	if err != nil {
		return proof, err
	}
	if !ok || nonce == "" || proof.Version <= 0 || proof.Input.UserID != userID || proof.Issuer != s.cfg.Token.Issuer || !SecretEqual(proof.NonceHash, sha256Hex(nonce)) || proof.AuthenticatedAt.IsZero() || proof.AuthenticatedAt.After(time.Now().Add(time.Minute)) || time.Since(proof.AuthenticatedAt) > 10*time.Minute {
		return proof, jwt.ErrTokenUnverifiable
	}
	proof.expected = raw
	proof.nonce = nonce
	return proof, nil
}

func independentFactor(proof loginProof, factor TwoFactorFactor) bool {
	return !hasAuthMethod(proof.Input.AuthMethods, factor.Method) || (factor.Method != "email" && factor.Method != "sms")
}

func (s *engine) loginFactors(proof loginProof, settings *TwoFactorSettings) []TwoFactorFactor {
	var factors []TwoFactorFactor
	if settings == nil || !settings.Enabled {
		return factors
	}
	for _, f := range settings.Factors {
		if f.Enabled && s.TwoFactorMethodAvailable(f.Method) && independentFactor(proof, f) {
			factors = append(factors, f)
		}
	}
	return factors
}

func (s *engine) finishFirstFactor(ctx context.Context, proof loginProof) (LoginOutcome, error) {
	if proof.Version <= 0 || len(proof.Input.AuthMethods) == 0 {
		return LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return LoginOutcome{}, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	user, err := s.lockAuthenticationAccount(ctx, q, proof.Input.UserID, proof.Version, proof.SessionID == "")
	if err != nil {
		return LoginOutcome{}, err
	}
	if err := s.bindRecoveryGeneration(ctx, tx, user, &proof); err != nil {
		return LoginOutcome{}, err
	}
	if err := s.validateLoginProofSource(ctx, tx, proof); err != nil {
		return LoginOutcome{}, err
	}
	settings, settingsErr := s.get2FASettings(ctx, q, user.ID)
	status, statusErr := s.MFAStatusWith(settings, settingsErr)
	if statusErr != nil {
		return LoginOutcome{}, statusErr
	}
	if len(proof.expected) > 0 {
		if err := s.claimProof(ctx, keyTwoFactorChallenge+user.ID, proof.expected); err != nil {
			return LoginOutcome{}, err
		}
	}
	// Enrollment/challenge selection is shared by password, passwordless and
	// providers. A verified UV passkey has already completed MFA itself.
	completedMFA := hasAuthMethod(proof.Input.AuthMethods, "mfa")
	needsChallenge := s.TwoFactorEnabled() && status.Enabled && status.Satisfied && !completedMFA
	gateErr := s.requireSessionMFAStateOn(ctx, tx, user.ID, proof.Input.AuthMethods, status, nil)
	if gateErr != nil && !errors.Is(gateErr, ErrTwoFAEnrollmentRequired) && !errors.Is(gateErr, ErrTwoFARequired) {
		return LoginOutcome{}, gateErr
	}
	out := LoginOutcome{UserID: user.ID, ReturnTo: proof.ReturnTo}
	if needsChallenge || gateErr != nil {
		// Enrollment JWTs authorize account mutations. A deleted account may
		// complete an existing factor, but never receives an enrollment token.
		if proof.DeletionID != "" && !needsChallenge {
			return LoginOutcome{}, gateErr
		}
		nonce := RandB64(32)
		proof.NonceHash = sha256Hex(nonce)
		proof.Issuer = s.cfg.Token.Issuer
		proof.Enrollment = !needsChallenge
		if proof.AuthenticatedAt.IsZero() {
			proof.AuthenticatedAt = time.Now().UTC()
		}
		if err := s.ephemSetJSON(ctx, keyTwoFactorChallenge+user.ID, proof, 10*time.Minute); err != nil {
			return LoginOutcome{}, err
		}
		if needsChallenge {
			out.Kind = LoginTwoFactorRequired
			out.Challenge, err = s.sendLoginFactor(ctx, user, proof, nonce, settings, "")
			if err != nil {
				return LoginOutcome{}, err
			}
		} else {
			out.Kind = LoginTwoFAEnrollmentRequired
			for _, method := range s.TwoFactorAllowedMethods() {
				if (method != "email" || user.Email != nil && strings.TrimSpace(*user.Email) != "") && independentFactor(proof, TwoFactorFactor{Method: method}) {
					out.AllowedMethods = append(out.AllowedMethods, method)
				}
			}
			authTime, amr, acr := (SessionFreshness{LastAuthenticatedAt: proof.AuthenticatedAt, AuthMethods: proof.Input.AuthMethods}).AssuranceClaims()
			token, expires, err := s.mintAccessTokenForUserWithAssurance(ctx, user, &status, map[string]any{"2fa_enrollment": true}, 10*time.Minute, &accessTokenAssurance{AuthTime: authTime, AMR: amr, ACR: acr, JTI: nonce})
			if err != nil {
				return LoginOutcome{}, err
			}
			tokens := authkit.NewTokenSet(token, "", expires)
			out.Enrollment = &tokens
		}
		if err := tx.Commit(ctx); err != nil {
			return LoginOutcome{}, err
		}
		return out, nil
	}
	if proof.SessionID != "" && !completedMFA {
		return LoginOutcome{}, ErrStepUpRequired
	}
	if proof.DeletionID != "" {
		return s.finishRecoveryProof(ctx, tx, proof)
	}
	session, _, evicted, err := s.issueLoginSessionTx(ctx, q, user, status, proof.Input)
	if err != nil {
		return LoginOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LoginOutcome{}, err
	}
	s.logSessionEvictions(ctx, user.ID, evicted)
	s.LogSessionCreated(ctx, user.ID, proof.Input.Event, session.SessionID, nullable(proof.Input.IP), nullable(proof.Input.UserAgent))
	out.Kind = LoginSessionIssued
	out.Session = &session
	return out, nil
}

func (s *engine) sendLoginFactor(ctx context.Context, user *User, proof loginProof, nonce string, settings *TwoFactorSettings, factorID string) (*TwoFactorChallenge, error) {
	factors := s.loginFactors(proof, settings)
	var selected *TwoFactorFactor
	for i := range factors {
		if factorID != "" {
			if factors[i].ID == factorID {
				selected = &factors[i]
				break
			}
		} else if selected == nil || factors[i].IsDefault {
			selected = &factors[i]
		}
	}
	if selected == nil {
		if factorID != "" || settings == nil || len(settings.BackupCodes) == 0 {
			return nil, ErrInvalidCode
		}
		return &TwoFactorChallenge{Method: "backup_code", Challenge: nonce, Factors: factors}, nil
	}
	destination, err := s.send2FACodeForUser(ctx, user, "login:"+proof.NonceHash, *selected)
	if err != nil {
		return nil, err
	}
	return &TwoFactorChallenge{Method: selected.Method, Destination: destination, Challenge: nonce, Factor: *selected, Factors: factors}, nil
}

// ResendLoginChallenge changes the selected independent factor while retaining
// the first-factor proof and its original expiry.
func (s *engine) ResendLoginChallenge(ctx context.Context, userID, nonce, factorID string) (*TwoFactorChallenge, error) {
	proof, err := s.loadLoginProof(ctx, userID, nonce)
	if err != nil || proof.Enrollment {
		return nil, jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	user, err := s.lockAuthenticationAccount(ctx, q, userID, proof.Version, proof.DeletionID != "")
	if err != nil {
		return nil, err
	}
	if err := s.bindRecoveryGeneration(ctx, tx, user, &proof); err != nil {
		return nil, err
	}
	proof, err = s.loadLoginProof(ctx, userID, nonce)
	if err != nil {
		return nil, err
	}
	if err := s.validateLoginProofSource(ctx, tx, proof); err != nil {
		return nil, err
	}
	settings, err := s.get2FASettings(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	return s.sendLoginFactor(ctx, user, proof, nonce, settings, factorID)
}

// CompleteLoginChallenge gives one current first-factor grant one successful
// second-factor completion and commits its session while holding the account lock.
func (s *engine) CompleteLoginChallenge(ctx context.Context, in LoginChallengeInput) (LoginOutcome, error) {
	proof, err := s.loadLoginProof(ctx, in.UserID, in.Challenge)
	if err != nil || proof.Enrollment {
		return LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return LoginOutcome{}, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	user, err := s.lockAuthenticationAccount(ctx, q, in.UserID, proof.Version, proof.DeletionID != "")
	if err != nil {
		return LoginOutcome{}, err
	}
	if err := s.bindRecoveryGeneration(ctx, tx, user, &proof); err != nil {
		return LoginOutcome{}, err
	}
	if err := s.validateLoginProofSource(ctx, tx, proof); err != nil {
		return LoginOutcome{}, err
	}
	proof, err = s.loadLoginProof(ctx, in.UserID, in.Challenge)
	if err != nil {
		return LoginOutcome{}, err
	}
	settings, err := s.get2FASettings(ctx, q, in.UserID)
	if err != nil {
		return LoginOutcome{}, err
	}
	method := "backup_code"
	var valid bool
	if in.BackupCode {
		valid, err = s.verifyBackupCode(ctx, q, in.UserID, strings.TrimSpace(in.Code))
	} else {
		factors := s.loginFactors(proof, settings)
		var selected *TwoFactorFactor
		for i := range factors {
			if in.FactorID != "" {
				if factors[i].ID == in.FactorID {
					selected = &factors[i]
					break
				}
			} else if selected == nil || factors[i].IsDefault {
				selected = &factors[i]
			}
		}
		if selected == nil {
			return LoginOutcome{}, ErrInvalidCode
		}
		method = selected.Method
		if method == "totp" {
			valid, err = s.verifyTOTPFactorCodeOn(ctx, q, *selected, in.Code)
		} else {
			valid, err = s.consumeMFAStepUpCode(ctx, in.UserID, "login:"+proof.NonceHash, sha256Hex(in.Code), method)
		}
	}
	if err != nil {
		return LoginOutcome{}, err
	}
	if !valid {
		return LoginOutcome{}, ErrInvalidCode
	}
	if err := s.claimProof(ctx, keyTwoFactorChallenge+in.UserID, proof.expected); err != nil {
		return LoginOutcome{}, err
	}
	methods := append(append([]string(nil), proof.Input.AuthMethods...), method, "otp", "mfa")
	proof.Input.AuthMethods = normalizeAuthMethods(methods)
	proof.Input.IP = in.IP
	proof.Input.UserAgent = in.UserAgent
	status, err := s.MFAStatusWith(settings, nil)
	if err != nil {
		return LoginOutcome{}, err
	}
	if proof.DeletionID != "" {
		return s.finishRecoveryProof(ctx, tx, proof)
	}
	session, _, evicted, err := s.issueLoginSessionTx(ctx, q, user, status, proof.Input)
	if err != nil {
		return LoginOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LoginOutcome{}, err
	}
	s.logSessionEvictions(ctx, user.ID, evicted)
	s.LogSessionCreated(ctx, user.ID, proof.Input.Event, session.SessionID, nullable(in.IP), nullable(in.UserAgent))
	return LoginOutcome{Kind: LoginSessionIssued, UserID: user.ID, Session: &session, ReturnTo: proof.ReturnTo}, nil
}

type loginEnrollmentKey struct{}

func (s *engine) authorizeLoginEnrollment(ctx context.Context, in TwoFactorEnrollInput) (context.Context, error) {
	if in.Mode != FirstFactorOnly {
		return ctx, nil
	}
	proof, err := s.loadLoginProof(ctx, in.UserID, in.LoginChallenge)
	if err != nil || !proof.Enrollment {
		return ctx, jwt.ErrTokenUnverifiable
	}
	version, err := s.q.UserCredentialVersion(ctx, in.UserID)
	if err != nil {
		return ctx, err
	}
	if version.CredentialVersion != proof.Version {
		return ctx, jwt.ErrTokenUnverifiable
	}
	if err := s.validateLoginProofSource(ctx, s.pg, proof); err != nil {
		return ctx, err
	}
	if strings.EqualFold(strings.TrimSpace(in.Method), "email") && (version.Email == nil || strings.TrimSpace(*version.Email) == "") {
		return ctx, ErrInvalidTwoFAMethod
	}
	if !independentFactor(proof, TwoFactorFactor{Method: strings.ToLower(strings.TrimSpace(in.Method))}) {
		return ctx, ErrInvalidTwoFAMethod
	}
	return context.WithValue(ctx, loginEnrollmentKey{}, proof), nil
}

func (s *engine) completeFactorEnrollment(ctx context.Context, in TwoFactorEnrollInput, out TwoFactorEnrollOutcome) (TwoFactorEnrollOutcome, error) {
	proof, ok := ctx.Value(loginEnrollmentKey{}).(loginProof)
	if !ok {
		return out, nil
	}
	if out.Method == "totp" || out.Method == "sms" || out.Method == "email" {
		proof.Input.AuthMethods = append(append([]string(nil), proof.Input.AuthMethods...), out.Method, "otp", "mfa")
	}
	proof.Input.UserAgent = in.UserAgent
	proof.Input.IP = in.IP
	login, err := s.finishFirstFactor(ctx, proof)
	if err != nil {
		return TwoFactorEnrollOutcome{}, err
	}
	out.Login = &login
	return out, nil
}

func (s *engine) validateLoginProofSource(ctx context.Context, source db.DBTX, proof loginProof) error {
	q := db.New(source)
	if proof.ProviderIssuer != "" {
		if proof.ProviderID == "" {
			return jwt.ErrTokenUnverifiable
		}
		var id string
		err := source.QueryRow(ctx, `SELECT id::text FROM user_providers WHERE id=$1::uuid AND user_id=$2::uuid AND issuer=$3 AND subject=$4 AND verified_at IS NOT NULL FOR UPDATE`, proof.ProviderID, proof.Input.UserID, proof.ProviderIssuer, proof.ProviderSubject).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return jwt.ErrTokenUnverifiable
		}
		if err != nil {
			return err
		}
	}
	if proof.PasskeyID != "" {
		var id string
		err := source.QueryRow(ctx, `SELECT id::text FROM user_passkeys WHERE id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL FOR UPDATE`, proof.PasskeyID, proof.Input.UserID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return jwt.ErrTokenUnverifiable
		}
		if err != nil {
			return err
		}
	}
	if proof.SessionID != "" {
		_, err := q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: proof.Input.UserID, SessionID: proof.SessionID, Issuer: s.cfg.Token.Issuer})
		if errors.Is(err, pgx.ErrNoRows) {
			return jwt.ErrTokenUnverifiable
		}
		return err
	}
	return nil
}

// ContinueRefreshMFA is called only after validating the refresh credential.
// An old session must repeat a first factor before sensitive factor enrollment.
func (s *engine) ContinueRefreshMFA(ctx context.Context, userID, sessionID string) (LoginOutcome, error) {
	fresh, err := s.SessionFreshness(ctx, userID, sessionID, time.Now())
	if err != nil {
		return LoginOutcome{}, err
	}
	if time.Since(fresh.LastAuthenticatedAt) > 10*time.Minute {
		return LoginOutcome{}, ErrStepUpRequired
	}
	version, err := s.q.UserCredentialVersion(ctx, userID)
	if err != nil {
		return LoginOutcome{}, err
	}
	return s.finishFirstFactor(ctx, loginProof{Version: version.CredentialVersion, AuthenticatedAt: fresh.LastAuthenticatedAt, SessionID: sessionID, Input: LoginSessionInput{UserID: userID, AuthMethods: fresh.AuthMethods, Event: "refresh_mfa"}})
}
