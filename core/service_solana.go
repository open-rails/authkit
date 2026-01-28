package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/siws"
)

// SolanaIssuer is the issuer string used for Solana wallet authentication.
const SolanaIssuer = "solana:mainnet"

// SolanaProviderSlug is the provider slug used for Solana wallets.
const SolanaProviderSlug = "solana"

// GenerateSIWSChallenge creates a new SIWS challenge for the given address.
// The challenge is stored in the cache and must be verified within 15 minutes.
func (s *Service) GenerateSIWSChallenge(ctx context.Context, cache siws.ChallengeCache, domain, address, username string) (siws.SignInInput, error) {
	// Validate the address format
	if err := siws.ValidateAddress(address); err != nil {
		return siws.SignInInput{}, fmt.Errorf("invalid solana address: %w", err)
	}

	// Create the sign-in input with defaults
	opts := []siws.InputOption{}
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
// Returns access token, expiry, refresh token, user ID, and whether a new user was created.
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

	// Verify the address matches
	if challengeData.Address != output.Account.Address {
		return "", time.Time{}, "", "", false, fmt.Errorf("address mismatch")
	}

	// Verify timestamps
	if err := siws.ValidateTimestamps(parsedInput); err != nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("timestamp validation failed: %w", err)
	}

	// Verify the cryptographic signature
	if err := siws.VerifySignature(output); err != nil {
		return "", time.Time{}, "", "", false, fmt.Errorf("signature verification failed: %w", err)
	}

	// Check if wallet is already linked to a user
	existingUserID, _, err := s.GetProviderLinkByIssuer(ctx, SolanaIssuer, output.Account.Address)
	if err == nil && existingUserID != "" {
		// Existing user - login
		userID = existingUserID
		created = false
	} else {
		// New user - create account
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
		if err := s.LinkProviderByIssuer(ctx, userID, SolanaIssuer, SolanaProviderSlug, output.Account.Address, nil); err != nil {
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

	// Verify the address matches
	if challengeData.Address != output.Account.Address {
		return fmt.Errorf("address mismatch")
	}

	// Verify timestamps
	if err := siws.ValidateTimestamps(parsedInput); err != nil {
		return fmt.Errorf("timestamp validation failed: %w", err)
	}

	// Verify the cryptographic signature
	if err := siws.VerifySignature(output); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Check if wallet is already linked to another user
	existingUserID, _, err := s.GetProviderLinkByIssuer(ctx, SolanaIssuer, output.Account.Address)
	if err == nil && existingUserID != "" {
		if existingUserID == userID {
			// Already linked to this user - success (no-op)
			return nil
		}
		return fmt.Errorf("wallet already linked to another account")
	}

	// Link wallet to user
	return s.LinkProviderByIssuer(ctx, userID, SolanaIssuer, SolanaProviderSlug, output.Account.Address, nil)
}

// GetUserBySolanaAddress looks up a user by their Solana wallet address.
func (s *Service) GetUserBySolanaAddress(ctx context.Context, address string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}

	userID, _, err := s.GetProviderLinkByIssuer(ctx, SolanaIssuer, address)
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
	err := s.pg.QueryRow(ctx, `
		SELECT subject FROM profiles.user_providers
		WHERE user_id = $1 AND issuer = $2
	`, userID, SolanaIssuer).Scan(&address)

	if err != nil {
		return "", nil // No wallet linked
	}
	return address, nil
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
	var exists bool
	err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.users WHERE username = $1)`, username).Scan(&exists)
	return exists, err
}
