package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/internal/testoutbox"
)

// A provider login finishing its second factor keeps the provider link it
// started from locked until the session is committed: an unlink racing the
// completion waits for it. The apitest TestProviderAuthenticationWorkflow runs
// the rest of the continuation.
func TestProviderLoginHoldsItsLinkUntilTheSessionCommits(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	f := newAccountFlow(t, pg.Pool, newServerTestConfig())
	for kind, build := range map[string]func(*testidp.IdP, string, ...authprovider.Option) authprovider.Provider{
		"oidc": (*testidp.IdP).OIDC, "oauth2": (*testidp.IdP).OAuth2,
	} {
		t.Run(kind, func(t *testing.T) {
			f.t = t
			ctx := t.Context()
			provider := build(testidp.New(t), "race-provider")
			f.service.SetProviders(provider)
			f.mount() // providers are configured before the public mount is built
			verified := true
			identity := providerTestIdentity{Subject: "race-" + uniqueSuffix(), Email: uniqueEmail("provider-race"), Verified: &verified}
			first, _ := f.providerLogin(provider, identity, "", false)
			f.expect(200, first)
			uid, _, err := f.service.Backend().GetProviderLinkByIssuer(ctx, provider.Issuer(), identity.Subject)
			require.NoError(t, err)
			// A password keeps the unlink from removing the last login method.
			require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(ctx, uid, "Provider-backup-password-123"))
			phone := uniquePhone()
			_, err = fixtureBackend(f.service.Backend()).enableFactor(ctx, uid, "sms", &phone, authflow.AllowAdditionalFactors)
			require.NoError(t, err)

			next, _ := f.providerLogin(provider, identity, "", false)
			f.expect(403, next)
			require.Equal(t, "2fa_required", next.Error.Code)
			body := map[string]any{"user_id": uid, "challenge": next.Error.Metadata.Challenge, "code": lastSent(f.sms, testoutbox.LoginCode).Code}
			unlink := func(ctx context.Context) error {
				removed, err := f.service.Backend().UnlinkProviderUnlessLast(ctx, uid, provider.Name())
				if err != nil {
					return err
				}
				if !removed {
					return fmt.Errorf("provider unlink refused")
				}
				return nil
			}
			completed := f.completeWhileRevoking(uid, func() flowResponse { return f.post("/2fa/verify", body) }, unlink)
			f.expect(200, completed)
			f.session(completed.TokenSet, "oauth", "sms", "otp", "mfa")
			_, _, err = f.service.Backend().GetProviderLinkByIssuer(ctx, provider.Issuer(), identity.Subject)
			require.Error(t, err, "the unlink ran after the session committed")
		})
	}
}
