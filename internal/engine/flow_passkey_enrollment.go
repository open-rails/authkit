package engine

import (
	"context"
	"errors"
	jwt "github.com/golang-jwt/jwt/v5"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

// BeginPasskeyMFAEnrollment is the mandatory-upgrade path, not ordinary key
// management. Only the live, nonce-bound primary proof may fill its first slot.
func (s *Engine) BeginPasskeyMFAEnrollment(ctx context.Context, in authflow.TwoFactorEnrollInput) (*protocol.CredentialCreation, error) {
	ctx, proof, err := s.passkeyEnrollmentProof(ctx, in)
	if err != nil {
		return nil, err
	}
	if err := s.firstPasskeySlot(ctx, s.pg, in.UserID); err != nil {
		return nil, err
	}
	user, err := s.passkeyUser(ctx, in.UserID, true)
	if err != nil {
		return nil, err
	}
	if user.credentialVersion != proof.Version {
		return nil, errmodel.E(errmodel.CodeInvalidChallenge)
	}
	return s.beginPasskeyCreation(ctx, user, passkeyPurposeMFAEnrollment, proof.NonceHash)
}

// FinishPasskeyMFAEnrollment commits the key and the UV-proven session under
// one account lock. A parallel factor enrollment, reset or proof supersession
// cannot turn a stale primary proof into a new credential or another session.
func (s *Engine) FinishPasskeyMFAEnrollment(ctx context.Context, in authflow.TwoFactorEnrollInput, response []byte) (authflow.LoginOutcome, error) {
	ctx, proof, err := s.passkeyEnrollmentProof(ctx, in)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return authflow.LoginOutcome{}, errmodel.E(errmodel.CodeInvalidRequest)
	}
	binding, session, err := s.consumePasskeySession(ctx, parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return authflow.LoginOutcome{}, errmodel.E(errmodel.CodeInvalidChallenge)
	}
	if binding.Purpose != passkeyPurposeMFAEnrollment || binding.UserID != in.UserID || binding.CredentialVersion != proof.Version || !secret.Equal(binding.LoginChallenge, proof.NonceHash) {
		return authflow.LoginOutcome{}, errmodel.E(errmodel.CodeInvalidChallenge)
	}
	user, err := s.passkeyUser(ctx, in.UserID, true)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	credential, err := s.createCredential(user, session, parsed)
	if err != nil {
		return authflow.LoginOutcome{}, errmodel.E(errmodel.CodeInvalidRequest)
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if _, err := s.lockLoginAccount(ctx, q, in.UserID, proof.Version); err != nil {
		return authflow.LoginOutcome{}, err
	}
	if _, err := s.loadLoginProof(ctx, in.UserID, in.LoginChallenge); err != nil {
		return authflow.LoginOutcome{}, errmodel.E(errmodel.CodeInvalidChallenge)
	}
	if err := s.validateLoginProofSource(ctx, tx, proof); err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := s.firstPasskeySlot(ctx, tx, in.UserID); err != nil {
		return authflow.LoginOutcome{}, err
	}
	key, err := s.insertPasskeyOn(ctx, q, in.UserID, credential, nil)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	proof.PasskeyID = key.ID
	proof.Input.AuthMethods = authflow.NormalizeAuthMethods(append(proof.Input.AuthMethods, "swk", "mfa"))
	proof.Input.UserAgent, proof.Input.IP = in.UserAgent, in.IP
	proof.AuthenticatedAt = time.Now().UTC()
	return s.finishFirstFactorTx(ctx, tx, proof)
}

func (s *Engine) passkeyEnrollmentProof(ctx context.Context, in authflow.TwoFactorEnrollInput) (context.Context, loginProof, error) {
	if !s.PasskeysEnabled() || !s.TwoFactorEnabled() || in.Mode != authflow.FirstFactorOnly || strings.TrimSpace(in.UserID) == "" || in.SessionID != "" {
		return ctx, loginProof{}, errmodel.E(errmodel.CodeInvalidChallenge)
	}
	in.Method = "passkey"
	authorized, err := s.authorizeLoginEnrollment(ctx, in)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return ctx, loginProof{}, errmodel.E(errmodel.CodeInvalidChallenge)
		}
		return ctx, loginProof{}, err
	}
	proof, ok := authorized.Value(loginEnrollmentKey{}).(loginProof)
	if !ok {
		return ctx, loginProof{}, errmodel.E(errmodel.CodeInvalidChallenge)
	}
	return authorized, proof, nil
}

func (s *Engine) firstPasskeySlot(ctx context.Context, source db.DBTX, userID string) error {
	required, err := s.userRequiresMFA(ctx, source, userID)
	if err != nil {
		return err
	}
	if !required {
		return errmodel.E(errmodel.CodeInvalidChallenge)
	}
	factors, err := db.New(source).MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return err
	}
	held, err := s.holdsAnyPasskey(ctx, source, userID)
	if err != nil {
		return err
	}
	strong := false
	for _, factor := range factors {
		strong = strong || strongFactorMethod(factor.Method)
	}
	if strong || held {
		return errmodel.ErrTwoFAFactorExists
	}
	return nil
}
