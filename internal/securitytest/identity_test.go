package securitytest

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/verify"
	neutral "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

// delegatedAppToken is a token a registered application signs for one of its
// own users: typ delegated-access+jwt, the user in delegated_sub.
func delegatedAppToken(t *testing.T, s keys.Signer, iss, user string) string {
	t.Helper()
	now := time.Now()
	token, err := jose.Sign(context.Background(), s, jose.DelegatedAccessTokenType, jwt.MapClaims{
		"iss": iss, "aud": []string{audience}, "delegated_sub": user, "jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	require.NoError(t, err)
	return token
}

// TestSecurityIdentitySubjectInvokerCredential: each credential AuthKit
// accepts names the Subject whose authority it uses (a native user or
// application), the Invoker who acts (the subject itself unless an
// application acts for one of its users) and itself as the Credential,
// never as the subject. Read through a gate over the Client, as a billing
// library reads it (Client.Identity).
func TestSecurityIdentitySubjectInvokerCredential(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(withDeviceKeys), authtest.WithConfig(func(c *authkit.Config) {
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{audience}}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{}, nil
		}
	}))
	identity := gated(h.auth, verify.Required(h.auth))
	identityOf := func(t *testing.T, credential string) neutral.Identity {
		t.Helper()
		return callerOf(t, identity(t, bearer(credential)))
	}
	self := func(t *testing.T, id neutral.Identity) {
		t.Helper()
		require.True(t, id.SelfInvoked(), "the subject acts for itself: %+v", id)
		require.Equal(t, neutral.Invoker{Issuer: id.Issuer, ID: id.Subject}, id.Invoker)
	}
	user := h.newAccount("iduser")
	sessionOf := func(t *testing.T, token string) string {
		t.Helper()
		cl, err := h.auth.Verify(ctx, token)
		require.NoError(t, err)
		require.NotEmpty(t, cl.SessionID)
		return cl.SessionID
	}

	t.Run("browser session", func(t *testing.T) {
		token := h.login(user).AccessToken
		id := identityOf(t, token)
		require.Equal(t, neutral.Identity{
			Issuer: issuer, Subject: user.id, SubjectKind: neutral.SubjectUser,
			Invoker:    neutral.Invoker{Issuer: issuer, ID: user.id},
			Credential: neutral.Credential{Kind: neutral.CredentialSession, ID: sessionOf(t, token)},
			Email:      user.email, Username: user.username, EmailVerified: true,
		}, id)
	})

	t.Run("device key: the owning user is the subject", func(t *testing.T) {
		pub, priv := ed25519Key(t)
		dk := h.deviceKeyClient()
		enrollment, err := dk.BeginEnrollment(ctx, user.email, pub, "phone")
		require.NoError(t, err)
		device, err := dk.FinishEnrollment(ctx, enrollment, priv, h.verificationCode(user.email), "")
		require.NoError(t, err)
		id := identityOf(t, device.AccessToken)
		require.Equal(t, user.id, id.Subject)
		require.Equal(t, neutral.SubjectUser, id.SubjectKind)
		require.Equal(t, neutral.Credential{Kind: neutral.CredentialDeviceKey, ID: device.DeviceKey.ID}, id.Credential)
		self(t, id)
	})

	t.Run("group API key: the group's account, stable across rotation", func(t *testing.T) {
		owner := h.newAccount("idowner")
		group, _ := h.newOrg(owner)
		key := func(name string) (iam.APIKey, string) {
			k, secret, err := createKey(h.auth, ctx, iam.UserActor(owner.id), group, iam.NewAPIKey{Name: name, Role: roleIn(t, h.auth, group, "member")})
			require.NoError(t, err)
			return k, secret
		}
		first, firstSecret := key("ci")
		second, secondSecret := key("ci")
		a, b := identityOf(t, firstSecret), identityOf(t, secondSecret)
		require.Equal(t, group.ID(), a.Subject)
		require.Equal(t, neutral.SubjectApplication, a.SubjectKind)
		require.Equal(t, neutral.Credential{Kind: neutral.CredentialAPIKey, ID: first.ID}, a.Credential)
		require.Equal(t, neutral.Credential{Kind: neutral.CredentialAPIKey, ID: second.ID}, b.Credential)
		require.Equal(t, a.Subject, b.Subject, "rotating keys keeps the subject")
		self(t, a)

		require.NoError(t, h.auth.RevokeAPIKey(ctx, iam.UserActor(owner.id), group, first.ID))
		requireStatus(t, identity(t, bearer(firstSecret)), http.StatusUnauthorized, "api_key_revoked")
		require.Equal(t, a.Subject, identityOf(t, secondSecret).Subject, "a revoked credential leaves its subject")
	})

	signer := newSigner(t, "identity-app")
	const appIssuer = "https://identity-app.security.test"
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), iam.RemoteApplication{
		Issuer: appIssuer, PublicKeys: staticKeys(t, signer), Enabled: true,
	})
	require.NoError(t, err)

	t.Run("application by its signed token", func(t *testing.T) {
		id := identityOf(t, appToken(t, signer, appIssuer))
		require.Equal(t, issuer, id.Issuer, "the deployment that registered it vouches")
		require.Equal(t, app.ID, id.Subject)
		require.Equal(t, neutral.SubjectApplication, id.SubjectKind)
		require.Equal(t, neutral.CredentialSignedToken, id.Credential.Kind)
		self(t, id)
	})

	t.Run("an application's user invokes the application", func(t *testing.T) {
		id := identityOf(t, delegatedAppToken(t, signer, appIssuer, "u_42"))
		require.Equal(t, app.ID, id.Subject, "the application's authority and money")
		require.Equal(t, neutral.SubjectApplication, id.SubjectKind)
		require.Equal(t, neutral.Invoker{Issuer: appIssuer, ID: "u_42"}, id.Invoker, "the foreign user acting")
		require.False(t, id.SelfInvoked())
		require.Equal(t, neutral.CredentialSignedToken, id.Credential.Kind)
		require.Empty(t, id.Email, "a foreign invoker's subject has no account to read")
	})

	t.Run("a token delegated from a user is the user", func(t *testing.T) {
		token, err := h.auth.MintDelegatedAccessToken(ctx, iam.SystemActor(), iam.DelegatedAccess{Subject: user.id, Audiences: []string{audience}})
		require.NoError(t, err)
		id := identityOf(t, token.Value)
		require.Equal(t, user.id, id.Subject)
		require.Equal(t, neutral.CredentialAccessToken, id.Credential.Kind)
		self(t, id)
	})

	t.Run("a revoked session is refused, the user's other sign-in is not", func(t *testing.T) {
		stale, fresh := h.login(user).AccessToken, h.login(user).AccessToken
		require.NoError(t, h.auth.RevokeSession(ctx, iam.UserActor(user.id), user.id, sessionOf(t, stale)))
		required := gated(h.auth, h.auth.Required())
		requireStatus(t, required(t, bearer(stale)), http.StatusUnauthorized, "session_revoked")
		require.Equal(t, user.id, callerOf(t, required(t, bearer(fresh))).Subject)
	})

	t.Run("only the Client's gates prove an identity", func(t *testing.T) {
		requireStatus(t, gated(h.auth)(t, bearer(h.login(user).AccessToken)), 299, "")
	})
}
