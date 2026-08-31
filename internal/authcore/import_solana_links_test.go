package authcore

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/jwtkit"
)

func TestImportedSolanaLinkRequiresSIWSVerification(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	userID := mkBareUser(t, ctx, svc, "imported-solana")

	challenge, parsed, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
	address := output.Account.Address
	result, err := svc.importUnverifiedSolanaLink(ctx, ImportUnverifiedSolanaLinkInput{
		UserID:   userID,
		Address:  address,
		Source:   "legacy_wallets",
		SourceID: "42",
	})
	if err != nil {
		t.Fatalf("ImportUnverifiedSolanaLink: %v", err)
	}
	if result.Status != ImportUnverifiedSolanaLinkInserted {
		t.Fatalf("import status = %q, want inserted (reason=%q)", result.Status, result.Reason)
	}
	// The generic provider-link API is not proof-aware and must not be able to
	// promote an imported Solana row. Only LinkSolanaWallet after SIWS may do so.
	if err := svc.LinkProviderByIssuer(ctx, userID, svc.solanaIssuer(), SolanaProviderSlug, address, nil); err != nil {
		t.Fatalf("generic same-user provider link: %v", err)
	}

	account, err := svc.GetSolanaLinkedAccount(ctx, userID)
	if err != nil {
		t.Fatalf("GetSolanaLinkedAccount before proof: %v", err)
	}
	if account == nil || account.Verified || account.VerifiedAt != nil || account.Address != address {
		t.Fatalf("imported account must be visible but unverified: %#v", account)
	}
	if got, err := svc.GetSolanaAddress(ctx, userID); err != nil || got != "" {
		t.Fatalf("GetSolanaAddress before proof = %q, %v; want empty, nil", got, err)
	}
	if got := svc.CountProviderLinks(ctx, userID); got != 0 {
		t.Fatalf("CountProviderLinks before proof = %d, want 0", got)
	}
	if _, _, err := svc.GetProviderLinkByIssuer(ctx, svc.solanaIssuer(), address); err != pgx.ErrNoRows {
		t.Fatalf("trusted provider lookup before proof error = %v, want pgx.ErrNoRows", err)
	}
	slugs, _, err := svc.UserProfileLinks(ctx, userID)
	if err != nil {
		t.Fatalf("UserProfileLinks before proof: %v", err)
	}
	if len(slugs) != 0 {
		t.Fatalf("provider slugs before proof = %v, want none", slugs)
	}

	cache := memorystore.NewSIWSCache(15 * time.Minute)
	t.Cleanup(func() { _ = cache.Close() })
	if err := cache.Put(ctx, parsed.Nonce, challenge); err != nil {
		t.Fatalf("store SIWS challenge: %v", err)
	}
	withSolanaSNSTestProxy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"s":"ok","result":{"reverse":"","stale":false}}`))
	})
	if err := svc.LinkSolanaWallet(ctx, cache, userID, output); err != nil {
		t.Fatalf("LinkSolanaWallet proof: %v", err)
	}

	account, err = svc.GetSolanaLinkedAccount(ctx, userID)
	if err != nil {
		t.Fatalf("GetSolanaLinkedAccount after proof: %v", err)
	}
	if account == nil || !account.Verified || account.VerifiedAt == nil || account.Address != address {
		t.Fatalf("proved account must be verified: %#v", account)
	}
	if got, err := svc.GetSolanaAddress(ctx, userID); err != nil || got != address {
		t.Fatalf("GetSolanaAddress after proof = %q, %v; want %q, nil", got, err, address)
	}
	if got := svc.CountProviderLinks(ctx, userID); got != 1 {
		t.Fatalf("CountProviderLinks after proof = %d, want 1", got)
	}

	var verificationRequired bool
	var migrationSource string
	if err := pool.QueryRow(ctx, `
		SELECT (profile->>'verification_required')::boolean, profile->>'migration_source'
		FROM profiles.user_providers
		WHERE user_id=$1::uuid AND issuer=$2 AND subject=$3
	`, userID, svc.solanaIssuer(), address).Scan(&verificationRequired, &migrationSource); err != nil {
		t.Fatalf("read promoted provenance: %v", err)
	}
	if verificationRequired || migrationSource != "legacy_wallets" {
		t.Fatalf("promotion must preserve provenance and clear requirement: required=%v source=%q", verificationRequired, migrationSource)
	}
}

func TestLinkSolanaWalletRequiresUnlinkBeforeAddressChange(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	for _, verified := range []bool{false, true} {
		name := "imported"
		if verified {
			name = "verified"
		}
		t.Run(name, func(t *testing.T) {
			userID := mkBareUser(t, ctx, svc, "change-requires-unlink-"+name)
			_, _, currentWallet := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
			currentAddress := currentWallet.Account.Address

			if verified {
				if _, err := pool.Exec(ctx, `
					INSERT INTO profiles.user_providers (user_id, issuer, provider_slug, subject, verified_at)
					VALUES ($1::uuid, $2, $3, $4, now())
				`, userID, svc.solanaIssuer(), SolanaProviderSlug, currentAddress); err != nil {
					t.Fatalf("insert verified wallet: %v", err)
				}
			} else {
				result, err := svc.importUnverifiedSolanaLink(ctx, ImportUnverifiedSolanaLinkInput{
					UserID: userID, Address: currentAddress, Source: "legacy_wallets", SourceID: name,
				})
				if err != nil || result.Status != ImportUnverifiedSolanaLinkInserted {
					t.Fatalf("import current wallet = %#v, %v", result, err)
				}
			}

			challenge, parsed, replacementWallet := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
			cache := memorystore.NewSIWSCache(15 * time.Minute)
			t.Cleanup(func() { _ = cache.Close() })
			if err := cache.Put(ctx, parsed.Nonce, challenge); err != nil {
				t.Fatalf("store replacement challenge: %v", err)
			}

			err := svc.LinkSolanaWallet(ctx, cache, userID, replacementWallet)
			if !errors.Is(err, ErrWalletChangeRequiresUnlink) {
				t.Fatalf("LinkSolanaWallet error = %v, want ErrWalletChangeRequiresUnlink", err)
			}

			account, err := svc.GetSolanaLinkedAccount(ctx, userID)
			if err != nil {
				t.Fatalf("GetSolanaLinkedAccount: %v", err)
			}
			if account == nil || account.Address != currentAddress || account.Verified != verified {
				t.Fatalf("current wallet changed after rejected replacement: %#v", account)
			}
			if _, _, found, err := svc.getSolanaProviderLinkAny(ctx, replacementWallet.Account.Address); err != nil || found {
				t.Fatalf("replacement wallet persisted: found=%v err=%v", found, err)
			}
		})
	}
}

func TestImportUnverifiedSolanaLinksReportsIdempotenceAndConflicts(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	userA := mkBareUser(t, ctx, svc, "import-solana-a")
	userB := mkBareUser(t, ctx, svc, "import-solana-b")
	_, _, outputA := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
	_, _, outputB := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))

	inputs := []ImportUnverifiedSolanaLinkInput{
		{UserID: userA, Address: outputA.Account.Address, Source: "legacy_wallets", SourceID: "1"},
		{UserID: userA, Address: outputA.Account.Address, Source: "legacy_wallets", SourceID: "1"},
		{UserID: userB, Address: outputA.Account.Address, Source: "legacy_wallets", SourceID: "2"},
		{UserID: userA, Address: outputB.Account.Address, Source: "legacy_wallets", SourceID: "3"},
		{UserID: userA, Address: "not-a-wallet", Source: "legacy_wallets", SourceID: "4"},
	}
	result, err := svc.ImportUnverifiedSolanaLinks(ctx, inputs)
	if err != nil {
		t.Fatalf("ImportUnverifiedSolanaLinks: %v", err)
	}
	if result.Inserted != 1 || result.Skipped != 1 || result.Rejected != 3 {
		t.Fatalf("batch counts = inserted:%d skipped:%d rejected:%d", result.Inserted, result.Skipped, result.Rejected)
	}
	if len(result.Results) != len(inputs) {
		t.Fatalf("result count = %d, want %d", len(result.Results), len(inputs))
	}
	wantStatuses := []ImportUnverifiedSolanaLinkStatus{
		ImportUnverifiedSolanaLinkInserted,
		ImportUnverifiedSolanaLinkSkipped,
		ImportUnverifiedSolanaLinkRejected,
		ImportUnverifiedSolanaLinkRejected,
		ImportUnverifiedSolanaLinkRejected,
	}
	wantReasons := []string{"", "already_imported", "address_owned_by_other_user", "user_has_different_address", "invalid_address"}
	for i, item := range result.Results {
		if item.Index != i || item.UserID != inputs[i].UserID || item.Address != inputs[i].Address {
			t.Fatalf("result[%d] identity = %#v, want input %#v", i, item, inputs[i])
		}
		if item.Status != wantStatuses[i] || item.Reason != wantReasons[i] {
			t.Fatalf("result[%d] = %#v, want status %q reason %q", i, item, wantStatuses[i], wantReasons[i])
		}
	}
}

func TestImportedSolanaLinkCanBeUnlinkedWithoutAnotherCredential(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	userID := mkBareUser(t, ctx, svc, "import-solana-unlink")
	_, _, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))

	result, err := svc.importUnverifiedSolanaLink(ctx, ImportUnverifiedSolanaLinkInput{
		UserID: userID, Address: output.Account.Address, Source: "legacy_wallets", SourceID: "unlink-1",
	})
	if err != nil || result.Status != ImportUnverifiedSolanaLinkInserted {
		t.Fatalf("import = %#v, %v", result, err)
	}

	removed, err := svc.UnlinkProviderUnlessLast(ctx, userID, SolanaProviderSlug)
	if err != nil || !removed {
		t.Fatalf("unlink imported claim = %v, %v; want true, nil", removed, err)
	}
	account, err := svc.GetSolanaLinkedAccount(ctx, userID)
	if err != nil || account != nil {
		t.Fatalf("linked account after unlink = %#v, %v; want nil, nil", account, err)
	}
}

func TestImportedSolanaLinkCanLoginOnlyAfterValidSIWSProof(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	signer, err := jwtkit.NewRSASigner(2048, "solana-import-test")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	svc := NewService(Config{
		Token:        TokenConfig{Issuer: "https://test", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}},
		Registration: RegistrationConfig{NativeUserMode: RegistrationModeClosed},
	}, Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"solana-import-test": signer.PublicKey()}}, WithPostgres(pool))
	userID := mkBareUser(t, ctx, svc, "import-solana-login")
	challenge, parsed, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
	result, err := svc.importUnverifiedSolanaLink(ctx, ImportUnverifiedSolanaLinkInput{
		UserID: userID, Address: output.Account.Address, Source: "legacy_wallets", SourceID: "login-1",
	})
	if err != nil || result.Status != ImportUnverifiedSolanaLinkInserted {
		t.Fatalf("import = %#v, %v", result, err)
	}

	cache := memorystore.NewSIWSCache(15 * time.Minute)
	t.Cleanup(func() { _ = cache.Close() })
	if err := cache.Put(ctx, parsed.Nonce, challenge); err != nil {
		t.Fatalf("store SIWS challenge: %v", err)
	}
	withSolanaSNSTestProxy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"s":"ok","result":{"reverse":"","stale":false}}`))
	})
	accessToken, _, refreshToken, gotUserID, created, err := svc.VerifySIWSAndLogin(ctx, cache, output, nil)
	if err != nil {
		t.Fatalf("VerifySIWSAndLogin: %v", err)
	}
	if gotUserID != userID || created || accessToken == "" || refreshToken == "" {
		t.Fatalf("login result user=%q created=%v access=%v refresh=%v", gotUserID, created, accessToken != "", refreshToken != "")
	}
	account, err := svc.GetSolanaLinkedAccount(ctx, userID)
	if err != nil || account == nil || !account.Verified || account.VerifiedAt == nil {
		t.Fatalf("account after SIWS login = %#v, %v", account, err)
	}
}
