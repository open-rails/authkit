package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/siws"
)

// SolanaProviderSlug is the provider slug used for Solana wallets.
const SolanaProviderSlug = "solana"

func normalizeSolanaNetwork(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	if network != "" {
		switch network {
		case "mainnet", "mainnet-beta":
			return "mainnet"
		case "testnet":
			return "testnet"
		case "devnet":
			return "devnet"
		default:
			return network
		}
	}
	return ""
}

func solanaChainIDForOptions(opts Options) string {
	if n := normalizeSolanaNetwork(opts.SolanaNetwork); n != "" {
		return n
	}
	if isDevEnvironment(opts.Environment) {
		return "testnet"
	}
	return "mainnet"
}

func (s *Service) solanaChainID() string {
	if s == nil {
		return solanaChainIDForOptions(Options{})
	}
	return solanaChainIDForOptions(s.opts)
}

func (s *Service) solanaIssuer() string {
	return "solana:" + s.solanaChainID()
}

// GenerateSIWSChallenge creates a new SIWS challenge for the given address.
// The challenge is stored in the cache and must be verified within 15 minutes.
func (s *Service) GenerateSIWSChallenge(ctx context.Context, cache siws.ChallengeCache, domain, address, username string) (siws.SignInInput, error) {
	// Validate the address format
	if err := siws.ValidateAddress(address); err != nil {
		return siws.SignInInput{}, fmt.Errorf("invalid solana address: %w", err)
	}

	// Create the sign-in input with defaults
	opts := []siws.InputOption{
		siws.WithChainID(s.solanaChainID()),
	}
	if s.opts.BaseURL != "" {
		opts = append(opts, siws.WithURI(s.opts.BaseURL))
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
		ExpiresAt: now.Add(15 * time.Minute),
		Input:     input,
	}

	if err := cache.Put(ctx, input.Nonce, challengeData); err != nil {
		return siws.SignInInput{}, fmt.Errorf("failed to store challenge: %w", err)
	}

	return input, nil
}

// VerifySIWSAndLogin verifies a SIWS signature and logs in or creates a user.
// Returns service token, expiry, refresh token, user ID, and whether a new user was created.
func (s *Service) VerifySIWSAndLogin(ctx context.Context, cache siws.ChallengeCache, output siws.SignInOutput, extra map[string]any) (accessToken string, expiresAt time.Time, refreshToken, userID string, created bool, err error) {
	if s.pg == nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("postgres not configured")
	}

	// Parse the signed message to get the input fields
	parsedInput, err := siws.ParseMessage(string(output.SignedMessage))
	if err != nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("failed to parse signed message: %w", err)
	}

	// Look up the challenge by nonce
	challengeData, found, err := cache.Get(ctx, parsedInput.Nonce)
	if err != nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("failed to lookup challenge: %w", err)
	}
	if !found {
		return "", time.Time{}, "", "", false, fmt.Errorf("challenge not found or expired")
	}

	// Delete the nonce immediately (single-use)
	_ = cache.Del(ctx, parsedInput.Nonce)

	// Run the stateless verification (expiry, address, domain, timestamps,
	// public-key consistency, signature) against the server-issued challenge.
	if err := verifySIWSChallenge(challengeData, parsedInput, output, time.Now().UTC()); err != nil {
		return "", time.Time{}, "", "", false, err
	}

	// Check if wallet is already linked to a user
	existingUserID, _, err := s.GetProviderLinkByIssuer(ctx, s.solanaIssuer(), output.Account.Address)
	if err == nil && existingUserID != "" {
		// Existing user - login
		userID = existingUserID
		created = false
	} else {
		// New user - create account. Blocked when public registration is
		// disabled: an existing wallet still logs in via the branch above, but
		// no NEW account may be auto-created here.
		if !s.opts.PublicNativeUserRegistrationEnabled() {
			return "", time.Time{}, "", "", false, ErrRegistrationDisabled
		}
		username := challengeData.Username
		if username == "" {
			username = s.deriveSolanaUsername(output.Account.Address)
		}
		// Ensure username is unique
		username = s.ensureUniqueUsername(ctx, username)

		// Create user with no email/phone
		u, err := s.createUser(ctx, "", username)
		if err != nil {
			return "", time.Time{}, "", "", false, fmt.Errorf("failed to create user: %w", err)
		}
		userID = u.ID
		created = true

		// Link wallet to user
		if err := s.LinkProviderByIssuer(ctx, userID, s.solanaIssuer(), SolanaProviderSlug, output.Account.Address, nil); err != nil {
			return "", time.Time{}, "", "", false, fmt.Errorf("failed to link wallet: %w", err)
		}
	}

	if err := s.ensureUserAccessByID(ctx, userID); err != nil {
		return "", time.Time{}, "", "", false, err
	}

	// Issue tokens
	if extra == nil {
		extra = make(map[string]any)
	}
	extra["provider"] = SolanaProviderSlug
	extra["solana_address"] = output.Account.Address

	sid, refreshToken, _, err := s.IssueRefreshSession(ctx, userID, "", nil)
	if err != nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("failed to create session: %w", err)
	}
	extra["sid"] = sid

	accessToken, expiresAt, err = s.IssueAccessToken(ctx, userID, "", extra)
	if err != nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("failed to issue token: %w", err)
	}

	// Log the login
	s.LogSessionCreated(ctx, userID, "solana_login", sid, nil, nil)

	return accessToken, expiresAt, refreshToken, userID, created, nil
}

// LinkSolanaWallet links a Solana wallet to an existing user account.
func (s *Service) LinkSolanaWallet(ctx context.Context, cache siws.ChallengeCache, userID string, output siws.SignInOutput) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	// Parse the signed message to get the nonce
	parsedInput, err := siws.ParseMessage(string(output.SignedMessage))
	if err != nil {
		return fmt.Errorf("failed to parse signed message: %w", err)
	}

	// Look up the challenge by nonce
	challengeData, found, err := cache.Get(ctx, parsedInput.Nonce)
	if err != nil {
		return fmt.Errorf("failed to lookup challenge: %w", err)
	}
	if !found {
		return fmt.Errorf("challenge not found or expired")
	}

	// Delete the nonce immediately (single-use)
	_ = cache.Del(ctx, parsedInput.Nonce)

	// Run the stateless verification against the server-issued challenge.
	if err := verifySIWSChallenge(challengeData, parsedInput, output, time.Now().UTC()); err != nil {
		return err
	}

	// Check if wallet is already linked to another user
	existingUserID, _, err := s.GetProviderLinkByIssuer(ctx, s.solanaIssuer(), output.Account.Address)
	if err == nil && existingUserID != "" {
		if existingUserID == userID {
			// Already linked to this user - success (no-op)
			return nil
		}
		return fmt.Errorf("wallet already linked to another account")
	}

	// Link wallet to user
	return s.LinkProviderByIssuer(ctx, userID, s.solanaIssuer(), SolanaProviderSlug, output.Account.Address, nil)
}

// GetUserBySolanaAddress looks up a user by their Solana wallet address.
func (s *Service) GetUserBySolanaAddress(ctx context.Context, address string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}

	userID, _, err := s.GetProviderLinkByIssuer(ctx, s.solanaIssuer(), address)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, nil
	}

	return s.getUserByID(ctx, userID)
}

// GetSolanaAddress retrieves the Solana wallet address linked to a user, if any.
func (s *Service) GetSolanaAddress(ctx context.Context, userID string) (string, error) {
	if s.pg == nil {
		return "", nil
	}

	var address string
	address, err := s.q.UserProviderSubjectByIssuer(ctx, db.UserProviderSubjectByIssuerParams{UserID: userID, Issuer: s.solanaIssuer()})
	if err != nil {
		return "", nil // No wallet linked
	}
	return address, nil
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
		return fmt.Errorf("challenge expired")
	}

	// Verify the address matches the one the challenge was issued for.
	if challengeData.Address != output.Account.Address {
		return fmt.Errorf("address mismatch")
	}

	// Bind the signed message's domain to the server-issued challenge domain
	// (anti-phishing). Field-level rather than strict byte-compare so wallets
	// that reconstruct the message text remain compatible.
	if err := siws.ValidateDomain(parsedInput, challengeData.Input.Domain); err != nil {
		return fmt.Errorf("domain validation failed: %w", err)
	}

	// Bind the chainId and URI the wallet signed to the server-issued challenge
	// when the server set them. Issue #51 hardened SIWS but left this as
	// optional; binding them closes a cross-network (e.g. devnet vs mainnet) and
	// cross-context replay gap. Only enforced when present on the challenge so
	// wallets that omit/reconstruct these fields are not falsely rejected.
	if want := challengeData.Input.ChainID; want != nil && *want != "" {
		if parsedInput.ChainID == nil || *parsedInput.ChainID != *want {
			return fmt.Errorf("chain id mismatch")
		}
	}
	if want := challengeData.Input.URI; want != nil && *want != "" {
		if parsedInput.URI == nil || *parsedInput.URI != *want {
			return fmt.Errorf("uri mismatch")
		}
	}

	// Verify the message timestamps (issuedAt skew, notBefore, expirationTime).
	if err := siws.ValidateTimestamps(parsedInput); err != nil {
		return fmt.Errorf("timestamp validation failed: %w", err)
	}

	// If the wallet supplied a public key, ensure it is consistent with the
	// address (the address is the source of truth for the provider link).
	if err := validateSolanaPublicKey(output.Account); err != nil {
		return err
	}

	// Verify the cryptographic signature.
	if err := siws.VerifySignature(output); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// validateSolanaPublicKey ensures that, when a wallet supplies an explicit
// public key, it is consistent with the account address. The address (base58 of
// the Ed25519 public key) remains the source of truth for verification and the
// provider link; this only rejects an inconsistent client payload.
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

// deriveSolanaUsername creates a username from a Solana address.
// Format: u_XXXX (first 4 chars of address)
func (s *Service) deriveSolanaUsername(address string) string {
	if len(address) < 4 {
		return "u_" + address
	}
	return "u_" + strings.ToLower(address[:4])
}

// ensureUniqueUsername appends a random suffix if username is taken.
func (s *Service) ensureUniqueUsername(ctx context.Context, username string) string {
	original := username
	for i := 0; i < 10; i++ {
		exists, err := s.usernameExists(ctx, username)
		if err != nil || !exists {
			return username
		}
		// Append random suffix
		username = original + "_" + randAlphanumeric(4)
	}
	// Last resort - use full random
	return "u_" + randAlphanumeric(8)
}

func (s *Service) usernameExists(ctx context.Context, username string) (bool, error) {
	if s.pg == nil {
		return false, nil
	}
	return s.q.UserUsernameExists(ctx, &username)
}
