package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
)

// A provider login finishing its second factor keeps the provider link it
// started from locked until the session is committed: an unlink racing the
// completion waits for it. The apitest TestProviderAuthenticationWorkflow runs
// the rest of the continuation.
func TestProviderLoginHoldsItsLinkUntilTheSessionCommits(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	for kind, build := range map[string]func(*testidp.IdP, string, ...provider.Option) provider.Provider{
		"oidc": (*testidp.IdP).OIDC, "oauth2": (*testidp.IdP).OAuth2,
	} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			idp := testidp.New(t)
			idpProvider := build(idp, "race-provider")
			cfg := testConfig()
			f := newAccountFlow(t, pg.Pool, cfg, config.Deps{Providers: []provider.Provider{idpProvider}})
			identity := testidp.Identity{Subject: "race-" + uniqueSuffix(), Email: uniqueEmail("provider-race"), EmailVerified: true}
			f.expect(200, f.providerSignIn(idp, idpProvider.Name(), identity, ""))
			uid, _, err := f.engine.GetProviderLinkByIssuer(ctx, idpProvider.Issuer(), identity.Subject)
			require.NoError(t, err)
			// A password keeps the unlink from removing the last login method.
			require.NoError(t, f.engine.adminSetPassword(ctx, uid, "Provider-backup-password-123"))
			phone := uniquePhone()
			_, err = f.engine.enableFactor(ctx, uid, "sms", &phone, authflow.AllowAdditionalFactors)
			require.NoError(t, err)

			next := f.expect(200, f.providerSignIn(idp, idpProvider.Name(), identity, ""))
			body := map[string]any{"user_id": uid, "challenge": next.challenge(t), "code": sentCode(t, f.sms, iam.MessageLoginCode)}
			unlink := func(ctx context.Context) error {
				removed, err := f.engine.UnlinkProviderUnlessLast(ctx, uid, idpProvider.Name())
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
			f.session(completed.tokens(), "oauth", "sms", "otp", "mfa")
			_, _, err = f.engine.GetProviderLinkByIssuer(ctx, idpProvider.Issuer(), identity.Subject)
			require.Error(t, err, "the unlink ran after the session committed")
		})
	}
}
