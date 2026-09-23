package embedded

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	totpSecretBytes = 20
	totpDigits      = 6
	totpPeriod      = 30
	totpEnrollTTL   = 10 * time.Minute

	keyTOTPEnrollment = "2fa:totp:enroll:"
)

// The pending secret is sealed with the same key as the committed one, so a
// dump of the ephemeral store is no weaker than a dump of Postgres.
type totpEnrollmentData struct {
	SealedSecret []byte `json:"sealed_secret"`
}

// StartTOTPEnrollment creates a short-lived pending authenticator-app secret.
func (s *engine) StartTOTPEnrollment(ctx context.Context, userID string) (secret, otpauthURI string, err error) {
	if !s.TwoFactorMethodAvailable(string(TwoFactorTOTP)) {
		return "", "", Err2FAMethodUnavailable
	}
	if _, err := aes.NewCipher(s.cfg.TwoFactor.TOTPSecretKey); err != nil {
		return "", "", fmt.Errorf("totp secret encryption key not configured")
	}
	if !s.useEphemeralStore() {
		return "", "", fmt.Errorf("ephemeral store not configured")
	}
	user, err := s.AdminGetUser(ctx, userID)
	if err != nil {
		return "", "", err
	}
	secret, err = generateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	sealed, err := s.encryptTOTPSecret(secret)
	if err != nil {
		return "", "", err
	}
	if err := s.ephemSetJSON(ctx, keyTOTPEnrollment+userID, totpEnrollmentData{SealedSecret: sealed}, totpEnrollTTL); err != nil {
		return "", "", err
	}
	label := userID
	if user.Email != nil && strings.TrimSpace(*user.Email) != "" {
		label = *user.Email
	} else if user.Username != nil && strings.TrimSpace(*user.Username) != "" {
		label = *user.Username
	}
	return secret, buildTOTPURI(s.cfg.Token.Issuer, label, secret), nil
}

// TOTPEnrollment completes a pending authenticator-app enrollment: Code is the
// current TOTP for the pending secret; MakeDefault promotes it to the user's
// default second factor; Mode is the deployment's factor-enrollment policy.
type TOTPEnrollment struct {
	UserID      string
	Code        string
	MakeDefault bool
	Mode        FactorEnrollmentMode
}

// EnableTOTP2FA verifies the pending secret and enables authenticator-app 2FA for
// the user, returning fresh backup codes.
func (s *engine) EnableTOTP2FA(ctx context.Context, in TOTPEnrollment) ([]string, error) {
	codes, _, err := s.enableTOTP2FA(ctx, in, "")
	return codes, err
}

// enableTOTP2FA also marks provenSessionID 2FA-verified (see enable2FA).
func (s *engine) enableTOTP2FA(ctx context.Context, in TOTPEnrollment, provenSessionID string) ([]string, bool, error) {
	userID := in.UserID
	if !s.TwoFactorMethodAvailable(string(TwoFactorTOTP)) {
		return nil, false, Err2FAMethodUnavailable
	}
	var pending totpEnrollmentData
	raw, ok, err := s.ephemReadJSON(ctx, keyTOTPEnrollment+userID, &pending)
	if err != nil {
		return nil, false, err
	}
	if !ok || len(pending.SealedSecret) == 0 {
		return nil, false, jwt.ErrTokenUnverifiable
	}
	secret, err := s.decryptTOTPSecret(pending.SealedSecret)
	if err != nil {
		return nil, false, err
	}
	step, validStep, err := matchingTOTPStep(secret, in.Code, time.Now())
	if err != nil {
		return nil, false, err
	}
	if !validStep {
		return nil, false, jwt.ErrTokenUnverifiable
	}
	if err := s.claimProof(ctx, keyTOTPEnrollment+userID, raw); err != nil {
		return nil, false, err
	}
	return s.enable2FA(ctx, factorEnable{
		UserID: userID, Method: "totp", TOTPSecret: pending.SealedSecret, LastTOTPStep: &step,
		MakeDefault: in.MakeDefault, Mode: in.Mode, ProvenSessionID: provenSessionID,
	})
}

func generateTOTPSecret() (string, error) {
	var b [totpSecretBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]), nil
}

func buildTOTPURI(issuer, label, secret string) string {
	if strings.TrimSpace(issuer) == "" {
		issuer = "AuthKit"
	}
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+label) + "?" + v.Encode()
}

func matchingTOTPStep(secret, code string, now time.Time) (int64, bool, error) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false, nil
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false, nil
		}
	}
	step := now.Unix() / totpPeriod
	for _, candidate := range []int64{step - 1, step, step + 1} {
		expected, err := totpCode(secret, candidate)
		if err != nil {
			return 0, false, err
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return candidate, true, nil
		}
	}
	return 0, false, nil
}

func totpCode(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1000000), nil
}

// totpKeyVersion is the 1-byte key-id/version prefix stamped on every encrypted
// TOTP secret (#148, lazy rotation). v1 builds no keyring; the prefix reserves the
// calibration knob so a future keyring/rotation is purely additive — old secrets
// stay decryptable by their prefix — with zero rotation machinery now.
const totpKeyVersion byte = 1

func (s *engine) encryptTOTPSecret(secret string) ([]byte, error) {
	block, err := aes.NewCipher(s.cfg.TwoFactor.TOTPSecretKey)
	if err != nil {
		return nil, fmt.Errorf("totp secret encryption key not configured")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Layout: [version byte] || nonce || GCM(nonce, secret). The version byte is
	// authenticated as additional data so it cannot be stripped/swapped silently.
	out := []byte{totpKeyVersion}
	return gcm.Seal(append(out, nonce...), nonce, []byte(secret), out), nil
}

func (s *engine) decryptTOTPSecret(data []byte) (string, error) {
	block, err := aes.NewCipher(s.cfg.TwoFactor.TOTPSecretKey)
	if err != nil {
		return "", fmt.Errorf("totp secret encryption key not configured")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Strip and verify the version prefix; an unknown version means a future
	// keyring stored it and this build cannot decrypt it.
	if len(data) < 1 || data[0] != totpKeyVersion {
		return "", jwt.ErrTokenUnverifiable
	}
	aad := data[:1]
	data = data[1:]
	if len(data) < gcm.NonceSize() {
		return "", jwt.ErrTokenUnverifiable
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SendPhone2FASetupCode generates and sends a 6-digit code for 2FA setup to the user's phone.
func (s *engine) SendPhone2FASetupCode(ctx context.Context, userID, phone, code string) error {
	hash := sha256Hex(code)
	// Store code in ephemeral store for 10 minutes, purpose: "2fa_setup"
	if s.useEphemeralStore() {
		if err := s.storePhoneVerification(ctx, "2fa_setup", phone, userID, hash, "", 10*time.Minute); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("ephemeral store not configured")
	}

	if s.sms != nil {
		msg := VerificationMessage{Code: code, Purpose: "2fa_setup"}
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		return smsDeliveryError(s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }))
	}
	// In production, require SMS to be configured
	if !s.cfg.Registration.AllowMissingSenders {
		return fmt.Errorf("SMS sender not configured")
	}
	return nil
}

// VerifyPhone2FASetupCode checks the code for 2FA phone setup.
func (s *engine) VerifyPhone2FASetupCode(ctx context.Context, userID, phone, code string) (bool, error) {
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "2fa_setup", phone, hash)
		if err != nil {
			return false, err
		}
		if uid != userID {
			return false, jwt.ErrTokenUnverifiable
		}
		return true, nil
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

const (
	keyEmail2FASetup         = "2fa:email-setup:"
	keyEmail2FASetupAttempts = "2fa:email-setup:attempts:"
	email2FASetupTTL         = 10 * time.Minute
	maxEmail2FASetupAttempts = 5
)

type email2FASetupData struct {
	Email    string `json:"email"`
	CodeHash string `json:"code_hash"`
}

// sendEmail2FASetupCode proves the account mailbox before it becomes a factor.
func (s *engine) sendEmail2FASetupCode(ctx context.Context, userID string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil || user.Email == nil || strings.TrimSpace(*user.Email) == "" {
		return ErrInvalidTwoFAMethod
	}
	code := randAlphanumeric(6)
	email := NormalizeEmail(*user.Email)
	if err := s.ephemSetJSON(ctx, keyEmail2FASetup+userID, email2FASetupData{Email: email, CodeHash: sha256Hex(code)}, email2FASetupTTL); err != nil {
		return err
	}
	_ = s.ephemDel(ctx, keyEmail2FASetupAttempts+userID)
	if s.email == nil {
		return fmt.Errorf("email sender not configured")
	}
	username := ""
	if user.Username != nil {
		username = *user.Username
	}
	msg := VerificationMessage{Code: code, Purpose: "2fa_setup"}
	sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
	return emailDeliveryError(s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
		return s.email.SendVerification(sendCtx, email, username, msg)
	}))
}

// verifyEmail2FASetupCode keeps the code on a miss; the attempt cap bounds
// guessing. A changed account email invalidates the code.
func (s *engine) verifyEmail2FASetupCode(ctx context.Context, userID, code string) (bool, error) {
	key := keyEmail2FASetup + userID
	var data email2FASetupData
	raw, ok, err := s.ephemReadJSON(ctx, key, &data)
	if err != nil {
		return false, err
	}
	if !ok || data.CodeHash == "" {
		return false, nil
	}
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user == nil || user.Email == nil || NormalizeEmail(*user.Email) != data.Email {
		_ = s.ephemDel(ctx, key)
		return false, nil
	}
	if !SecretEqual(data.CodeHash, sha256Hex(strings.TrimSpace(code))) {
		if s.recordFailedAttempt(ctx, keyEmail2FASetupAttempts+userID, email2FASetupTTL, maxEmail2FASetupAttempts) {
			_ = s.ephemDel(ctx, key)
		}
		return false, nil
	}
	if err := s.claimProof(ctx, key, raw); err != nil {
		return false, nil
	}
	_ = s.ephemDel(ctx, keyEmail2FASetupAttempts+userID)
	return true, nil
}
