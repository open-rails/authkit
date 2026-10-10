package securitytest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
	neutral "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

// TestSecurityIdentitySubjectInvokerCredential: each credential AuthKit
// accepts names the Subject whose authority it uses (a native user or a
// group's account), the Invoker who acts (the subject itself) and itself as
// the Credential, never as the subject. Read through the Client's
// Authenticator, as a library (OpenRails) reads it.
func TestSecurityIdentitySubjectInvokerCredential(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(withDeviceKeys))
	authenticate := func(credential string) (neutral.Verified, error) {
		r := httptest.NewRequest(http.MethodGet, resourceURL, nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		return h.auth.Authenticator().Authenticate(r)
	}
	identityOf := func(t *testing.T, credential string) neutral.Identity {
		t.Helper()
		v, err := authenticate(credential)
		require.NoError(t, err)
		return v.Identity()
	}
	refused := func(t *testing.T, credential string, want error) {
		t.Helper()
		v, err := authenticate(credential)
		require.Nil(t, v)
		require.ErrorIs(t, err, want)
		require.Equal(t, http.StatusUnauthorized, neutral.Refuse(nil, err).Status)
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
			k, secret, err := createKey(h.auth, ctx, iam.UserIdentity(owner.id), group, iam.NewAPIKey{Name: name, Role: roleIn(t, h.auth, group, "member")})
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

		require.NoError(t, h.auth.RevokeAPIKey(ctx, iam.UserIdentity(owner.id), group, first.ID))
		refused(t, firstSecret, neutral.ErrRevoked)
		require.Equal(t, a.Subject, identityOf(t, secondSecret).Subject, "a revoked credential leaves its subject")
	})

	t.Run("a revoked session is refused, the user's other sign-in is not", func(t *testing.T) {
		stale, fresh := h.login(user).AccessToken, h.login(user).AccessToken
		require.NoError(t, h.auth.RevokeSession(ctx, iam.UserIdentity(user.id), user.id, sessionOf(t, stale)))
		refused(t, stale, neutral.ErrRevoked)
		require.Equal(t, user.id, identityOf(t, fresh).Subject)
	})

	t.Run("only a gate over the Client proves an identity in the context", func(t *testing.T) {
		token := h.login(user).AccessToken
		r := httptest.NewRequest(http.MethodGet, resourceURL, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		_, ok := verify.VerifiedIdentity(r.Context(), h.auth)
		require.False(t, ok, "no gate ran")
		forged := verify.SetClaims(r.Context(), verify.Claims{Kind: verify.TokenUser, Issuer: issuer, UserID: user.id})
		_, ok = verify.VerifiedIdentity(forged, h.auth)
		require.False(t, ok, "stored claims prove nothing")
		id, ok := gateIdentity(h.auth, r)
		require.True(t, ok)
		require.Equal(t, user.id, id.Subject)
		_, err := authenticate("not-a-token")
		require.ErrorIs(t, err, neutral.ErrUnauthenticated)
	})
}

// TestSecurityIdentityStateIsAuthKits: authority comes only from the state
// AuthKit attaches to a credential. An identity built as a literal or decoded
// from JSON, "system" credential included, and the zero identity grant
// nothing; a pin to one group holds even where the application controls
// another.
func TestSecurityIdentityStateIsAuthKits(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	owner := h.newAccount("stateowner")
	groupA, _ := h.newOrg(owner)
	groupB, _ := h.newOrg(owner)
	member := roleIn(t, h.auth, groupB, "member")
	catalog := ident.Perm("org:catalog:read")
	ownerToken := h.login(owner).AccessToken
	verified := tokenIdentity(t, h.auth, ownerToken)
	can := func(who neutral.Identity, g iam.GroupRef) bool {
		t.Helper()
		ok, err := h.auth.Can(ctx, who, g, catalog)
		require.NoError(t, err)
		return ok
	}
	require.True(t, can(verified, groupB), "control: the owner's verified identity")

	t.Run("built or decoded identities grant nothing", func(t *testing.T) {
		literal := verified
		literal.Credential = neutral.Credential{Kind: verified.Credential.Kind, ID: verified.Credential.ID}
		b, err := json.Marshal(verified)
		require.NoError(t, err)
		var decoded neutral.Identity
		require.NoError(t, json.Unmarshal(b, &decoded))
		system := neutral.Identity{Credential: neutral.Credential{Kind: iam.CredentialSystem}}
		b, err = json.Marshal(iam.SystemIdentity())
		require.NoError(t, err)
		var decodedSystem neutral.Identity
		require.NoError(t, json.Unmarshal(b, &decodedSystem))
		require.Equal(t, iam.CredentialSystem, decodedSystem.Credential.Kind)
		for name, who := range map[string]neutral.Identity{"zero": {}, "literal": literal, "decoded": decoded, "literal system": system, "decoded system": decodedSystem} {
			require.False(t, can(who, groupB), name)
			_, err := h.auth.SetGroupRole(ctx, who, groupB, iam.UserSubject(h.newAccount("statetarget").id), member)
			require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
		}
		edited := iam.UserIdentity(h.newAccount("stateuser").id)
		edited.Subject, edited.Invoker.ID = owner.id, owner.id
		require.False(t, can(edited, groupB), "editing exported fields grants nothing")
	})

	t.Run("a pin holds where the application controls another group", func(t *testing.T) {
		app := h.registerApp(groupB, owner, "pinned-app", "member")
		self := iam.ApplicationIdentity(app.ID)
		require.True(t, can(self, groupB), "control: the application in the group it controls")
		require.True(t, can(iam.PinnedTo(self, groupB.ID()), groupB))
		pinned := iam.PinnedTo(self, groupA.ID())
		require.False(t, can(pinned, groupB), "pinned to A, refused in B though the application controls B")
		_, moved := iam.StateOf(iam.PinnedTo(pinned, groupB.ID()))
		require.False(t, moved, "narrowing never moves a pin")
	})
}
