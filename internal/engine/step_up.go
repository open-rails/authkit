package engine

// Step-up by each way an account signs in, beside a password, a second factor
// and an identity provider: a code sent to a proven address, a signature by
// the linked Solana wallet, or a passkey. Each proof is bound to the session
// that began it, single use and short-lived, and marks that session freshly
// authenticated with the method's amr. A code or a wallet is one factor, so it
// never re-proves an account with a second factor; a passkey is two.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/authkit/internal/siws"
)

const (
	keyStepUpCode = "step-up:code:" // +<userID>:<sessionID>
	keySIWSStepUp = "siws:step-up:" // +<nonce>
)

// siwsStepUp is a step-up's SIWS challenge and the session it re-authenticates.
type siwsStepUp struct {
	siws.ChallengeData
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

// stepUpMethods lists how userID can step up now.
func (s *Engine) stepUpMethods(ctx context.Context, userID string, settings *authflow.TwoFactorSettings) ([]string, error) {
	c := authflow.StepUpCredentials{SecondFactor: len(authflow.StepUpFactors(settings)) > 0}
	var err error
	if c.Password, err = s.HasPassword(ctx, userID); err != nil {
		return nil, err
	}
	if c.Passkey, err = s.holdsPasskey(ctx, s.pg, userID); err != nil {
		return nil, err
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	_, email := provenAddress(u, passwordlessChannelEmail)
	_, sms := provenAddress(u, passwordlessChannelSMS)
	c.Email, c.SMS = email && s.EmailAvailable(), sms && s.SMSAvailable()
	if _, err := s.linkedSolanaAddress(ctx, userID); err == nil {
		c.Solana = true
	} else if !errors.Is(err, errmodel.ErrProviderNotLinked) {
		return nil, err
	}
	slugs, err := s.ProviderSlugs(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, slug := range slugs {
		if s.providerSupportsStepUp(slug) {
			c.Providers = append(c.Providers, slug)
		}
	}
	return c.Methods(), nil
}

// singleFactorStepUp refuses a one-factor step-up for an account with a
// second factor: step_up_required says how it steps up. An unknown MFA state
// counts as enrolled.
func (s *Engine) singleFactorStepUp(ctx context.Context, userID string) error {
	if enrolled, err := s.HasUsableMFA(ctx, userID); err != nil || enrolled {
		return s.StepUpRequired(ctx, userID)
	}
	return nil
}

// markSteppedUp records a step-up by amr on the session.
func (s *Engine) markSteppedUp(ctx context.Context, userID, sessionID string, amr ...string) error {
	if err := s.MarkSessionAuthenticatedWithMethods(ctx, userID, sessionID, amr); err != nil {
		return errmodel.Internal("step_up_failed", err)
	}
	return nil
}

// provenAddress is u's address on channel ("email" or "sms") when it is proven.
func provenAddress(u *db.User, channel string) (string, bool) {
	switch {
	case u == nil:
	case channel == passwordlessChannelEmail && u.Email != nil && u.EmailVerified:
		return *u.Email, true
	case channel == passwordlessChannelSMS && u.PhoneNumber != nil && u.PhoneVerified:
		return *u.PhoneNumber, true
	}
	return "", false
}

func stepUpCodeKey(userID, sessionID string) string {
	return keyStepUpCode + userID + ":" + sessionID
}

// SendStepUpCode sends a code to the account's proven address on channel
// ("email" or "sms"). It replaces any code the session holds.
func (s *Engine) SendStepUpCode(ctx context.Context, userID, sessionID, channel string) error {
	if strings.TrimSpace(sessionID) == "" {
		return jwt.ErrTokenInvalidClaims
	}
	if err := s.singleFactorStepUp(ctx, userID); err != nil {
		return err
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	to, ok := provenAddress(u, channel)
	if !ok {
		return errmodel.E(errmodel.CodeContactNotVerified)
	}
	code := secret.Digits(6)
	if err := s.storeTwoFactorCode(ctx, stepUpCodeKey(userID, sessionID), twoFactorData{CodeHash: secret.Hash(code), Method: channel, Destination: to}); err != nil {
		return err
	}
	language := s.messageLanguage(ctx, deref(u.PreferredLanguage))
	if channel == passwordlessChannelSMS {
		return s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageLoginCode, To: to, Language: language, Code: code})
	}
	return s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageLoginCode, To: to, Username: deref(u.Username), Language: language, Code: code})
}

// StepUpWithCode re-authenticates the session with the code SendStepUpCode
// sent it, while the address it went to is still the account's, proven.
// ErrInvalidCode is a wrong code; ErrCodeExpired, no live one.
func (s *Engine) StepUpWithCode(ctx context.Context, userID, sessionID, code string) error {
	key := stepUpCodeKey(userID, sessionID)
	var sent twoFactorData
	if _, ok, err := s.ephemReadJSON(ctx, key, &sent); err != nil {
		return err
	} else if !ok {
		return errmodel.ErrCodeExpired
	}
	valid, err := s.consumeTwoFactorCode(ctx, key, secret.Hash(code), sent.Method)
	if err != nil {
		return err
	}
	if !valid {
		return errmodel.ErrInvalidCode
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if to, ok := provenAddress(u, sent.Method); !ok || to != sent.Destination {
		return errmodel.ErrCodeExpired
	}
	if err := s.singleFactorStepUp(ctx, userID); err != nil {
		return err
	}
	return s.markSteppedUp(ctx, userID, sessionID, sent.Method)
}

// linkedSolanaAddress is the wallet linked to userID on this network;
// ErrProviderNotLinked when there is none.
func (s *Engine) linkedSolanaAddress(ctx context.Context, userID string) (string, error) {
	if s.cfg.SolanaNetwork == "" {
		return "", errmodel.ErrProviderNotLinked
	}
	row, err := s.q.UserProviderByIssuerAny(ctx, db.UserProviderByIssuerAnyParams{UserID: userID, Issuer: s.solanaIssuer()})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errmodel.ErrProviderNotLinked
	}
	return row.Subject, err
}

// BeginSolanaStepUp issues a SIWS challenge for the account's linked wallet,
// bound to the session.
func (s *Engine) BeginSolanaStepUp(ctx context.Context, userID, sessionID, domain string) (siws.SignInInput, error) {
	if strings.TrimSpace(sessionID) == "" {
		return siws.SignInInput{}, jwt.ErrTokenInvalidClaims
	}
	if err := s.singleFactorStepUp(ctx, userID); err != nil {
		return siws.SignInInput{}, err
	}
	address, err := s.linkedSolanaAddress(ctx, userID)
	if err != nil {
		return siws.SignInInput{}, err
	}
	data, err := s.newSIWSChallenge(domain, address, siws.WithStatement("Confirm it's you."))
	if err != nil {
		return siws.SignInInput{}, err
	}
	if err := s.ephemSetJSON(ctx, keySIWSStepUp+data.Input.Nonce, siwsStepUp{ChallengeData: data, UserID: userID, SessionID: sessionID}, siwsChallengeTTL); err != nil {
		return siws.SignInInput{}, err
	}
	return data.Input, nil
}

// StepUpWithSolana re-authenticates the session with the linked wallet's
// signature over the challenge BeginSolanaStepUp issued it.
func (s *Engine) StepUpWithSolana(ctx context.Context, userID, sessionID string, output siws.SignInOutput) error {
	parsed, err := siws.ParseMessage(string(output.SignedMessage))
	if err != nil {
		return errmodel.E(errmodel.CodeAuthenticationFailed)
	}
	var challenge siwsStepUp
	found, err := s.ephemConsumeJSON(ctx, keySIWSStepUp+parsed.Nonce, &challenge)
	if err != nil {
		return err
	}
	if !found {
		return errmodel.ErrChallengeNotFound
	}
	if challenge.UserID != userID || challenge.SessionID != sessionID {
		return errmodel.ErrChallengeMismatch
	}
	if err := verifySIWSChallenge(challenge.ChallengeData, parsed, output, time.Now().UTC()); err != nil {
		if e := errmodel.As(err); e == nil || e.Status() >= 500 {
			err = errmodel.E(errmodel.CodeAuthenticationFailed)
		}
		return err
	}
	if address, err := s.linkedSolanaAddress(ctx, userID); err != nil {
		return err
	} else if address != output.Account.Address {
		return errmodel.ErrAddressMismatch
	}
	if err := s.singleFactorStepUp(ctx, userID); err != nil {
		return err
	}
	return s.markSteppedUp(ctx, userID, sessionID, "swk")
}

// BeginPasskeyStepUp starts an assertion by one of the account's passkeys,
// bound to the session.
func (s *Engine) BeginPasskeyStepUp(ctx context.Context, userID, sessionID string) (*protocol.CredentialAssertion, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, jwt.ErrTokenInvalidClaims
	}
	u, err := s.passkeyUser(ctx, userID, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && len(u.credentials) == 0 {
		return nil, errmodel.ErrPasskeyNotFound
	}
	if err != nil {
		return nil, err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	assertion, session, err := wa.BeginLogin(u, webauthn.WithUserVerification(s.passkeyUserVerification()))
	if err != nil {
		return nil, err
	}
	return assertion, s.storePasskeySession(ctx, session, passkeyPurposeStepUp, userID, sessionID)
}

// StepUpWithPasskey re-authenticates the session with the assertion
// BeginPasskeyStepUp asked for. A user-verified passkey is multi-factor, so it
// clears the gate on an account with a second factor too.
func (s *Engine) StepUpWithPasskey(ctx context.Context, userID, sessionID string, response []byte) error {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return errmodel.E(errmodel.CodeAuthenticationFailed)
	}
	data, session, err := s.consumePasskeySession(ctx, parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return errmodel.ErrChallengeNotFound
	}
	if data.Purpose != passkeyPurposeStepUp || data.UserID != userID || data.SessionID != sessionID {
		return errmodel.ErrChallengeMismatch
	}
	u, err := s.passkeyUser(ctx, userID, false)
	if err != nil {
		return err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return err
	}
	cred, err := wa.ValidateLogin(u, session, parsed)
	if err != nil {
		return errmodel.E(errmodel.CodeAuthenticationFailed)
	}
	if _, err := s.acceptAssertion(ctx, userID, parsed, cred); err != nil {
		return err
	}
	return s.markSteppedUp(ctx, userID, sessionID, "swk", "mfa")
}
