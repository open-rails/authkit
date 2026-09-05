package embedded

import (
	"context"
	"errors"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/internal/testdb"
)

// #78: a user with a verified wallet must unlink it before linking a different one.
func TestLinkSolanaWalletRequiresUnlinkBeforeAddressChange(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	userID := mkBareUser(t, ctx, svc, "change-requires-unlink")
	_, _, currentWallet := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
	currentAddress := currentWallet.Account.Address
	if _, err := pool.Exec(ctx, `
		INSERT INTO profiles.user_providers (user_id, issuer, provider_slug, subject, verified_at)
		VALUES ($1::uuid, $2, $3, $4, now())
	`, userID, svc.solanaIssuer(), SolanaProviderSlug, currentAddress); err != nil {
		t.Fatalf("insert verified wallet: %v", err)
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
	if account == nil || account.Address != currentAddress || !account.Verified {
		t.Fatalf("current wallet changed after rejected replacement: %#v", account)
	}
	if _, _, found, err := svc.getSolanaProviderLinkAny(ctx, replacementWallet.Account.Address); err != nil || found {
		t.Fatalf("replacement wallet persisted: found=%v err=%v", found, err)
	}
}
