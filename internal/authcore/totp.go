package authcore

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

	keyTOTPEnrollment = "auth:2fa:totp:enroll:"
)

type totpEnrollmentData struct {
	Secret string `json:"secret"`
}

// StartTOTPEnrollment creates a short-lived pending authenticator-app secret.
func (s *Service) StartTOTPEnrollment(ctx context.Context, userID string) (secret, otpauthURI string, err error) {
	if !s.TwoFactorMethodAvailable(string(TwoFactorTOTP)) {
		return "", "", Err2FAMethodUnavailable
	}
	if _, err := aes.NewCipher(s.opts.TOTPSecretKey); err != nil {
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
	if err := s.ephemSetJSON(ctx, keyTOTPEnrollment+userID, totpEnrollmentData{Secret: secret}, totpEnrollTTL); err != nil {
		return "", "", err
	}
	label := userID
	if user.Email != nil && strings.TrimSpace(*user.Email) != "" {
		label = *user.Email
	} else if user.Username != nil && strings.TrimSpace(*user.Username) != "" {
		label = *user.Username
	}
	return secret, buildTOTPURI(s.opts.Issuer, label, secret), nil
}

// EnableTOTP2FA verifies the pending secret and enables authenticator-app 2FA for
// the user, returning fresh backup codes. makeDefault sets it as the user's default
// second factor.
func (s *Service) EnableTOTP2FA(ctx context.Context, userID, code string, makeDefault bool) ([]string, error) {
	if !s.TwoFactorMethodAvailable(string(TwoFactorTOTP)) {
		return nil, Err2FAMethodUnavailable
	}
	var pending totpEnrollmentData
	ok, err := s.ephemGetJSON(ctx, keyTOTPEnrollment+userID, &pending)
	if err != nil || !ok || strings.TrimSpace(pending.Secret) == "" {
		return nil, jwt.ErrTokenUnverifiable
	}
	step, validStep, err := matchingTOTPStep(pending.Secret, code, time.Now())
	if err != nil || !validStep {
		return nil, jwt.ErrTokenUnverifiable
	}
	encrypted, err := s.encryptTOTPSecret(pending.Secret)
	if err != nil {
		return nil, err
	}
	codes, err := s.enable2FA(ctx, userID, "totp", nil, encrypted, &step, makeDefault)
	if err != nil {
		return nil, err
	}
	_ = s.ephemDel(ctx, keyTOTPEnrollment+userID)
	return codes, nil
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

func (s *Service) encryptTOTPSecret(secret string) ([]byte, error) {
	block, err := aes.NewCipher(s.opts.TOTPSecretKey)
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

func (s *Service) decryptTOTPSecret(data []byte) (string, error) {
	block, err := aes.NewCipher(s.opts.TOTPSecretKey)
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
func (s *Service) SendPhone2FASetupCode(ctx context.Context, userID, phone, code string) error {
	hash := sha256Hex(code)
	// Store code in ephemeral store for 10 minutes, purpose: "2fa_setup"
	if s.useEphemeralStore() {
		if err := s.storePhoneVerification(ctx, "2fa_setup", phone, userID, hash, 10*time.Minute); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("ephemeral store not configured")
	}

	if s.sms != nil {
		msg := VerificationMessage{Code: code}
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		return smsDeliveryError(s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }))
	}
	// In production, require SMS to be configured
	if !s.isDevEnvironment() {
		return fmt.Errorf("SMS sender not configured")
	}
	return nil
}

// VerifyPhone2FASetupCode checks the code for 2FA phone setup.
func (s *Service) VerifyPhone2FASetupCode(ctx context.Context, userID, phone, code string) (bool, error) {
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "2fa_setup", phone, hash)
		if err != nil {
			return false, err
		}
		if uid != userID {
			return false, fmt.Errorf("user_id mismatch")
		}
		return true, nil
	}
	return false, fmt.Errorf("ephemeral store not configured")
}
