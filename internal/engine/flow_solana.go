package engine

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/siws"
)

// SolanaProviderSlug is the provider slug used for Solana wallets.
const solanaProviderSlug = "solana"

func (s *Engine) solanaChainID() string {
	if s.cfg.SolanaNetwork != "" {
		return string(s.cfg.SolanaNetwork)
	}
	return string(iam.SolanaMainnet)
}

func (s *Engine) solanaIssuer() string {
	return "solana:" + s.solanaChainID()
}

// GenerateSIWSChallenge creates a new SIWS challenge for the given address.
// The challenge must be verified within 15 minutes.
func (s *Engine) GenerateSIWSChallenge(ctx context.Context, domain, address, username string) (siws.SignInInput, error) {
	// Validate the address format
	if err := siws.ValidateAddress(address); err != nil {
		return siws.SignInInput{}, fmt.Errorf("invalid solana address: %w", err)
	}

	// Create the sign-in input with defaults
	opts := []siws.InputOption{
		siws.WithChainID(s.solanaChainID()),
	}
	if s.cfg.Frontend.BaseURL != "" {
		opts = append(opts, siws.WithURI(s.cfg.Frontend.BaseURL))
	}

	input, err := siws.NewSignInInput(domain, address, opts...)
	if err != nil {
		return siws.SignInInput{}, fmt.Errorf("failed to create sign-in input: %w", err)
	}

	// Store challenge data
	now := time.Now().UTC()
	challengeData := siws.ChallengeData{
		Address:   address,
		Username:  username,
		IssuedAt:  now,
		ExpiresAt: now.Add(siwsChallengeTTL),
		Input:     input,
	}

	if err := s.ephemSetJSON(ctx, keySIWSNonce+input.Nonce, challengeData, siwsChallengeTTL); err != nil {
		return siws.SignInInput{}, fmt.Errorf("failed to store challenge: %w", err)
	}

	return input, nil
}

const (
	keySIWSNonce     = "siws:nonce:"
	siwsChallengeTTL = 15 * time.Minute
)

func (s *Engine) consumeSIWSChallenge(ctx context.Context, nonce string) (siws.ChallengeData, bool, error) {
	var d siws.ChallengeData
	ok, err := s.ephemConsumeJSON(ctx, keySIWSNonce+nonce, &d)
	return d, ok, err
}

// VerifySIWSAndLogin verifies a SIWS signature and logs in or creates a user.
// It shares the normal MFA/recovery/session tail with other first factors.
func (s *Engine) VerifySIWSAndLogin(ctx context.Context, output siws.SignInOutput, extra map[string]any) (authflow.LoginOutcome, error) {
	var userID string
	var created bool
	if s.pg == nil {
		return authflow.LoginOutcome{}, fmt.Errorf("postgres not configured")
	}

	// Parse the signed message to get the input fields
	parsedInput, err := siws.ParseMessage(string(output.SignedMessage))
	if err != nil {
		return authflow.LoginOutcome{}, fmt.Errorf("failed to parse signed message: %w", err)
	}

	// Consume the nonce (single-use): only one concurrent caller wins it, so a
	// replayed signed message cannot be verified twice (authkit #90).
	challengeData, found, err := s.consumeSIWSChallenge(ctx, parsedInput.Nonce)
	if err != nil {
		return authflow.LoginOutcome{}, fmt.Errorf("failed to consume challenge: %w", err)
	}
	if !found {
		return authflow.LoginOutcome{}, fmt.Errorf("%w", errmodel.ErrChallengeNotFound)
	}

	// Run the stateless verification (expiry, address, domain, timestamps,
	// public-key consistency, signature) against the server-issued challenge.
	if err := verifySIWSChallenge(challengeData, parsedInput, output, time.Now().UTC()); err != nil {
		return authflow.LoginOutcome{}, err
	}

	existingUserID, verified, found, err := s.getSolanaProviderLinkAny(ctx, output.Account.Address)
	if err != nil {
		return authflow.LoginOutcome{}, fmt.Errorf("look up Solana link: %w", err)
	}
	if found {
		userID = existingUserID
		created = false
		if !verified {
			if err := s.verifyImportedSolanaLink(ctx, userID, output.Account.Address); err != nil {
				return authflow.LoginOutcome{}, fmt.Errorf("verify imported Solana link: %w", err)
			}
		}
	} else {
		// New user - create account. Blocked when public registration is
		// disabled: an existing wallet still logs in via the branch above, but
		// no NEW account may be auto-created here.
		if !s.PublicNativeUserRegistrationEnabled() {
			return authflow.LoginOutcome{}, errmodel.ErrRegistrationDisabled
		}
		username := strings.TrimSpace(challengeData.Username)
		if username == "" || s.ValidateUsername(username) != nil || !s.usernameAvailable(ctx, username) {
			if username == "" {
				username = "u_" + output.Account.Address[:min(4, len(output.Account.Address))]
			}
			username = s.generateAvailableUsername(ctx, username)
		}

		// Create user with no email/phone
		u, err := s.createUser(ctx, "", username)
		if err != nil {
			return authflow.LoginOutcome{}, fmt.Errorf("failed to create user: %w", err)
		}
		userID = u.ID
		created = true

		// Link wallet to user
		if err := s.linkProvider(ctx, userID, iam.ProviderLink{Issuer: s.solanaIssuer(), Provider: solanaProviderSlug, Subject: output.Account.Address}); err != nil {
			return authflow.LoginOutcome{}, fmt.Errorf("failed to link wallet: %w", err)
		}
	}

	if extra == nil {
		extra = make(map[string]any)
	}
	extra["provider"] = solanaProviderSlug
	extra["solana_address"] = output.Account.Address

	link, err := s.q.UserProviderVerifiedLink(ctx, db.UserProviderVerifiedLinkParams{UserID: userID, Issuer: s.solanaIssuer(), Subject: output.Account.Address})
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	return s.finishFirstFactor(ctx, loginProof{ProviderID: link.ProviderID, ProviderIssuer: s.solanaIssuer(), ProviderSubject: output.Account.Address, Version: link.CredentialVersion, AuthenticatedAt: time.Now().UTC(), Created: created, Input: loginSessionInput{UserID: userID, AuthMethods: []string{"swk"}, Event: "solana_login", Extra: extra}})
}

// LinkSolanaWallet links the Solana wallet a SIWS output proves to an existing
// account and returns the account's linked wallet.
func (s *Engine) LinkSolanaWallet(ctx context.Context, userID string, output siws.SignInOutput) (authflow.SolanaLinkedAccount, error) {
	if err := s.linkSolanaWallet(ctx, userID, output); err != nil {
		return authflow.SolanaLinkedAccount{}, err
	}
	linked, err := s.getSolanaLinkedAccount(ctx, userID)
	if err == nil && linked == nil {
		err = errors.New("solana wallet missing after link")
	}
	if err != nil {
		return authflow.SolanaLinkedAccount{}, err
	}
	return *linked, nil
}

func (s *Engine) linkSolanaWallet(ctx context.Context, userID string, output siws.SignInOutput) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if err := s.RequireProvenContact(ctx, userID); err != nil {
		return err
	}

	// Parse the signed message to get the nonce
	parsedInput, err := siws.ParseMessage(string(output.SignedMessage))
	if err != nil {
		return fmt.Errorf("failed to parse signed message: %w", err)
	}

	// Consume the nonce exactly like the login path (AK security audit F5).
	challengeData, found, err := s.consumeSIWSChallenge(ctx, parsedInput.Nonce)
	if err != nil {
		return fmt.Errorf("failed to consume challenge: %w", err)
	}
	if !found {
		return fmt.Errorf("%w", errmodel.ErrChallengeNotFound)
	}

	// Run the stateless verification against the server-issued challenge.
	if err := verifySIWSChallenge(challengeData, parsedInput, output, time.Now().UTC()); err != nil {
		return err
	}

	// Check both verified and imported claims after proof. An imported address
	// can only be promoted for the user it was mapped to; ownership is never
	// transferred implicitly.
	existingUserID, verified, found, err := s.getSolanaProviderLinkAny(ctx, output.Account.Address)
	if err != nil {
		return fmt.Errorf("look up Solana link: %w", err)
	}
	if found {
		if existingUserID == userID {
			if verified {
				return nil
			}
			return s.verifyImportedSolanaLink(ctx, userID, output.Account.Address)
		}
		return fmt.Errorf("%w", errmodel.ErrWalletAlreadyLinked)
	}

	return s.linkVerifiedSolanaWallet(ctx, userID, output.Account.Address)
}

// linkVerifiedSolanaWallet creates the user's first Solana link without
// replacing an address already linked for the same issuer. The database's
// unique (user_id, issuer) constraint makes the rule atomic across concurrent
// requests; changing wallets requires an explicit unlink first.
func (s *Engine) linkVerifiedSolanaWallet(ctx context.Context, userID, address string) error {
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	providerSlug := solanaProviderSlug

	linked, err := s.q.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:           providerID,
		UserID:       userID,
		Issuer:       s.solanaIssuer(),
		ProviderSlug: &providerSlug,
		Subject:      address,
	})
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return errmodel.ErrWalletAlreadyLinked
		case isUniqueViolation(err, "user_providers_user_id_issuer_key"):
			return errmodel.ErrWalletChangeRequiresUnlink
		default:
			return err
		}
	}

	if linked.VerifiedAt != nil {
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, address)
	}
	return nil
}

// verifySIWSChallenge performs the stateless verification of a SIWS sign-in
// output against a stored challenge. It does not touch the database or cache, so
// it is unit-testable in isolation. parsedInput is the result of parsing
// output.SignedMessage; challengeData is the server-issued challenge looked up
// by nonce; now is the reference time (pass time.Now().UTC()).
//
// Checks, in order: server-issued expiry (authoritative, independent of the
// client-supplied expirationTime), address match, domain binding, message
// timestamps, public-key consistency, and the Ed25519 signature.
func verifySIWSChallenge(challengeData siws.ChallengeData, parsedInput siws.SignInInput, output siws.SignInOutput, now time.Time) error {
	// Enforce the server-issued expiry window. This is authoritative and does
	// not trust the client-supplied expirationTime in the signed message.
	if now.After(challengeData.ExpiresAt) {
		return fmt.Errorf("%w", errmodel.ErrChallengeExpired)
	}

	// Verify the address matches the one the challenge was issued for, and that
	// the address line the wallet actually signed names the same account.
	if challengeData.Address != output.Account.Address || parsedInput.Address != output.Account.Address {
		return fmt.Errorf("%w", errmodel.ErrAddressMismatch)
	}

	// Bind the signed message's domain to the server-issued challenge domain
	// (anti-phishing). Field-level rather than strict byte-compare so wallets
	// that reconstruct the message text remain compatible.
	if err := siws.ValidateDomain(parsedInput, challengeData.Input.Domain); err != nil {
		return fmt.Errorf("%w: %v", errmodel.ErrInvalidDomain, err)
	}

	// Bind the chainId and URI the wallet actually signed to the ones the server
	// issued. #51 hardened SIWS but left these two fields unbound, so a message
	// signed for devnet, or naming a different URI, still authenticated against a
	// mainnet challenge. The nonce is single-use and the signer owns the key, so
	// this is not an impersonation vector — it closes a cross-network /
	// cross-context replay gap. Enforced only for fields the SERVER set, the same
	// discipline the domain check uses, so a wallet that omits an optional field
	// the server never issued is not falsely rejected.
	if err := bindChallengeField("chain id", challengeData.Input.ChainID, parsedInput.ChainID); err != nil {
		return err
	}
	if err := bindChallengeField("uri", challengeData.Input.URI, parsedInput.URI); err != nil {
		return err
	}

	// Verify the message timestamps (issuedAt skew, notBefore, expirationTime).
	if err := siws.ValidateTimestamps(parsedInput); err != nil {
		return fmt.Errorf("%w: %v", errmodel.ErrInvalidTimestamp, err)
	}

	// If the wallet supplied a public key, ensure it is consistent with the
	// address (the address is the source of truth for the provider link).
	if err := validateSolanaPublicKey(output.Account); err != nil {
		return err
	}

	// Verify the cryptographic signature.
	if err := siws.VerifySignature(output); err != nil {
		return fmt.Errorf("%w: %v", errmodel.ErrInvalidSignature, err)
	}

	return nil
}

// validateSolanaPublicKey ensures that, when a wallet supplies an explicit
// public key, it is consistent with the account address. The address (base58 of
// the Ed25519 public key) remains the source of truth for verification and the
// provider link; this only rejects an inconsistent client payload.
// bindChallengeField requires the signed message to carry the same value the
// server issued for an optional SIWS field. A field the server did not set is
// unbound: the wallet may send anything, including nothing.
func bindChallengeField(name string, issued, signed *string) error {
	if issued == nil || *issued == "" {
		return nil
	}
	if signed == nil || *signed != *issued {
		return fmt.Errorf("%w: %s mismatch", errmodel.ErrChallengeMismatch, name)
	}
	return nil
}

func validateSolanaPublicKey(account siws.AccountInfo) error {
	if len(account.PublicKey) == 0 {
		return nil
	}
	if len(account.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length")
	}
	if siws.PublicKeyToBase58(account.PublicKey) != account.Address {
		return fmt.Errorf("public key does not match address")
	}
	return nil
}
