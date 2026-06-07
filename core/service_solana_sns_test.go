package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeSolanaSNSResolver struct {
	names map[string]string
	err   error
}

func (r fakeSolanaSNSResolver) ResolvePrimaryName(ctx context.Context, address string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	return r.names[address], nil
}

func TestNormalizeSolanaSNSName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: " Example.SOL ", want: "example.sol"},
		{in: "sub.example.sol", want: "sub.example.sol"},
	}
	for _, tt := range tests {
		got, err := normalizeSolanaSNSName(tt.in)
		if err != nil {
			t.Fatalf("normalizeSolanaSNSName(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("normalizeSolanaSNSName(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{"example", "example.eth", "bad name.sol"} {
		if _, err := normalizeSolanaSNSName(in); err == nil {
			t.Fatalf("normalizeSolanaSNSName(%q) expected error", in)
		}
	}
}

func TestSolanaSNSResolveAndStore(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	_, _, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
	address := output.Account.Address

	svc := NewService(Options{
		Issuer:                     "https://test",
		SolanaSNSEnabled:           true,
		SolanaSNSResolver:          fakeSolanaSNSResolver{names: map[string]string{address: "Example.SOL"}},
		SolanaSNSLookupTimeout:     time.Second,
		SolanaSNSCacheTTL:          time.Hour,
		NativeUserRegistrationMode: RegistrationModeOpen,
	}, Keyset{}).WithPostgres(pool)
	user := importSNSUser(t, ctx, svc, pool, "resolved")

	if err := svc.LinkProviderByIssuer(ctx, user.ID, svc.solanaIssuer(), SolanaProviderSlug, address, nil); err != nil {
		t.Fatalf("LinkProviderByIssuer: %v", err)
	}

	account, err := svc.GetSolanaLinkedAccount(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetSolanaLinkedAccount: %v", err)
	}
	if account == nil {
		t.Fatalf("expected linked account")
	}
	if account.Address != address || account.PrimarySNSName == nil || *account.PrimarySNSName != "example.sol" {
		t.Fatalf("unexpected account metadata: %+v", account)
	}
	if account.SNSResolutionStatus != SolanaSNSStatusResolved || account.SNSStale {
		t.Fatalf("unexpected SNS status: %+v", account)
	}
}

func TestSolanaSNSNotFoundAndResolverError(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	_, _, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
	address := output.Account.Address

	notFoundSvc := NewService(Options{
		Issuer:                 "https://test",
		SolanaSNSEnabled:       true,
		SolanaSNSResolver:      fakeSolanaSNSResolver{names: map[string]string{}},
		SolanaSNSLookupTimeout: time.Second,
		SolanaSNSCacheTTL:      time.Hour,
	}, Keyset{}).WithPostgres(pool)
	notFoundUser := importSNSUser(t, ctx, notFoundSvc, pool, "notfound")
	if err := notFoundSvc.LinkProviderByIssuer(ctx, notFoundUser.ID, notFoundSvc.solanaIssuer(), SolanaProviderSlug, address, nil); err != nil {
		t.Fatalf("LinkProviderByIssuer not found: %v", err)
	}
	notFoundAccount, err := notFoundSvc.GetSolanaLinkedAccount(ctx, notFoundUser.ID)
	if err != nil {
		t.Fatalf("GetSolanaLinkedAccount not found: %v", err)
	}
	if notFoundAccount.PrimarySNSName != nil || notFoundAccount.SNSResolutionStatus != SolanaSNSStatusNotFound {
		t.Fatalf("unexpected not-found account: %+v", notFoundAccount)
	}

	errorSvc := NewService(Options{
		Issuer:                 "https://test",
		SolanaNetwork:          "devnet",
		SolanaSNSEnabled:       true,
		SolanaSNSResolver:      fakeSolanaSNSResolver{err: errors.New("boom")},
		SolanaSNSLookupTimeout: time.Second,
		SolanaSNSCacheTTL:      time.Hour,
	}, Keyset{}).WithPostgres(pool)
	errorUser := importSNSUser(t, ctx, errorSvc, pool, "error")
	if err := errorSvc.LinkProviderByIssuer(ctx, errorUser.ID, errorSvc.solanaIssuer(), SolanaProviderSlug, address, nil); err != nil {
		t.Fatalf("LinkProviderByIssuer error: %v", err)
	}
	errorAccount, err := errorSvc.GetSolanaLinkedAccount(ctx, errorUser.ID)
	if err != nil {
		t.Fatalf("GetSolanaLinkedAccount error: %v", err)
	}
	if errorAccount.SNSResolutionStatus != SolanaSNSStatusError || errorAccount.SNSError == nil || *errorAccount.SNSError != solanaSNSProviderError {
		t.Fatalf("unexpected resolver-error account: %+v", errorAccount)
	}
}

func TestSolanaSNSDisabledMetadata(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	_, _, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))

	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	user := importSNSUser(t, ctx, svc, pool, "disabled")
	if err := svc.LinkProviderByIssuer(ctx, user.ID, svc.solanaIssuer(), SolanaProviderSlug, output.Account.Address, nil); err != nil {
		t.Fatalf("LinkProviderByIssuer: %v", err)
	}

	account, err := svc.GetSolanaLinkedAccount(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetSolanaLinkedAccount: %v", err)
	}
	if account == nil || account.SNSResolutionStatus != SolanaSNSStatusDisabled || account.PrimarySNSName != nil {
		t.Fatalf("unexpected disabled account: %+v", account)
	}
}

func importSNSUser(t *testing.T, ctx context.Context, svc *Service, pool *pgxpool.Pool, suffix string) *User {
	t.Helper()
	username := "sns" + suffix + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username) })
	user, err := svc.ImportUser(ctx, ImportUserInput{
		Email:         username + "@example.com",
		Username:      username,
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("ImportUser: %v", err)
	}
	return user
}
