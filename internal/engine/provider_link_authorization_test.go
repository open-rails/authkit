package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/passkeytest"
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
			unlink := func(ctx context.Context) error { return f.engine.UnlinkProvider(ctx, uid, idpProvider.Name()) }
			completed := f.completeWhileRevoking(uid, func() flowResponse { return f.post("/2fa/verify", body) }, unlink)
			f.expect(200, completed)
			f.session(completed.tokens(), "oauth", "sms", "otp", "mfa")
			_, _, err = f.engine.GetProviderLinkByIssuer(ctx, idpProvider.Issuer(), identity.Subject)
			require.Error(t, err, "the unlink ran after the session committed")
		})
	}
}

func TestPendingProviderLinkRechecksPasskeyOnlyPolicy(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(map[bool]string{false: "optional-key-control", true: "required-after-link-start"}[required], func(t *testing.T) {
			idp := testidp.New(t)
			p := idp.OAuth2("pending-provider")
			cfg := testConfig()
			cfg.Passkeys = config.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
			f := newAccountFlow(t, testdb.ScratchPostgres(t).Pool, cfg, config.Deps{Providers: []provider.Provider{p}})
			user := newUser(t, f.engine, "pendinglink")
			tokens := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})).tokens()
			claims, err := f.engine.Verify(t.Context(), tokens.AccessToken)
			require.NoError(t, err)
			// This is the server-owned authorization captured before redirecting to
			// the OAuth provider, when the original password session was sufficient.
			input := authflow.ExternalLoginInput{
				Link:     &authflow.ExternalLinkAuthorization{UserID: user.ID, SessionID: claims.SessionID, AuthenticatedAt: claims.AuthTime},
				Identity: authflow.ExternalIdentity{Provider: p.Name(), Issuer: p.Issuer(), Subject: "pending-" + uniqueSuffix(), Email: *user.Email, EmailVerified: true},
			}
			key := passkeytest.New(t, "https://app.example")
			creation, err := f.engine.BeginPasskeyRegistration(t.Context(), user.ID)
			require.NoError(t, err)
			_, err = f.engine.FinishPasskeyRegistration(t.Context(), user.ID, key.Register(t, creation))
			require.NoError(t, err)
			if required {
				_, err = f.engine.pg.Exec(t.Context(), `UPDATE users SET mfa_required=true WHERE id=$1`, user.ID)
				require.NoError(t, err)
			}
			result, err := f.engine.CompleteExternalLogin(t.Context(), input)
			if required {
				require.ErrorIs(t, err, errmodel.ErrStepUpRequired)
				_, _, lookupErr := f.engine.GetProviderLinkByIssuer(t.Context(), p.Issuer(), input.Identity.Subject)
				require.Error(t, lookupErr, "a pending weak link cannot attach a new credential after the policy changes")
				assertion, stepErr := f.engine.BeginPasskeyStepUp(t.Context(), user.ID, claims.SessionID)
				require.NoError(t, stepErr)
				require.NoError(t, f.engine.StepUpWithPasskey(t.Context(), user.ID, claims.SessionID, key.Assert(t, assertion, 1)))
				result, err = f.engine.CompleteExternalLogin(t.Context(), input)
			}
			require.NoError(t, err)
			require.Equal(t, authflow.LoginProviderLinked, result.Kind)
			require.Nil(t, result.Session, "linking does not create a replacement session")
			owner, _, err := f.engine.GetProviderLinkByIssuer(t.Context(), p.Issuer(), input.Identity.Subject)
			require.NoError(t, err)
			require.Equal(t, user.ID, owner)
		})
	}
}
