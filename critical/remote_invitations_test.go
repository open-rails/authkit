package critical_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
)

func TestCriticalRemoteInvitations(t *testing.T) {
	t.Run("AK-J15-C08_remote_acceptance_follows_native_redemption", func(t *testing.T) {
		const resource = "https://remote-invites.example"
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.Resource = authkit.ResourceConfig{ID: resource} }))
		ctx := t.Context()
		group, _, _ := f.ownedGroup(t)
		_, private, err := ed25519.GenerateKey(rand.Reader)
		noError(t, err)
		signer, err := keys.SignerFromKey("remote-invites", private)
		noError(t, err)
		jwk := keys.PublicJWK(signer.Public(), signer.KID(), signer.Algorithm())
		app, err := f.auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(group.ID), iam.RemoteApplication{
			Issuer: "https://remote-invites-" + uuid.NewString() + ".example", Enabled: true, Mode: iam.RemoteApplicationModeStatic,
			PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), JWK: &jwk}}})
		noError(t, err)
		// A trusted issuer's user with a verified email, as its token proves.
		remoteUser := func(t *testing.T, client *authkit.Client, email string) auth.Verified {
			t.Helper()
			now := time.Now()
			token := signJWT(t, signer, map[string]any{"alg": signer.Algorithm(), "kid": signer.KID(), "typ": "at+jwt"}, map[string]any{
				"iss": app.Issuer, "sub": "subject-" + email, "aud": resource, "client_id": "remote-ui", "iat": now.Unix(),
				"exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(), "email": email, "email_verified": true})
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, resource+"/invitations", nil)
			noError(t, err)
			r.Header.Set("Authorization", "Bearer "+token)
			v, err := client.Authenticator().Authenticate(r)
			noError(t, err)
			return v
		}
		invite := func(t *testing.T, client *authkit.Client, email string, role iam.Role) string {
			t.Helper()
			_, err := client.CreateInvitation(ctx, iam.SystemIdentity(), iam.GroupByID(group.ID), iam.NewInvitation{Email: email, Role: role})
			noError(t, err)
			pending, err := f.auth.RemoteInvitations(ctx, remoteUser(t, f.auth, email))
			noError(t, err)
			for _, inv := range pending {
				if inv.Role == role {
					return inv.ID
				}
			}
			t.Fatalf("%s has no pending %s invitation: %+v", email, role, pending)
			return ""
		}
		holds := func(t *testing.T, email string) iam.Role {
			t.Helper()
			roles, err := f.auth.RemoteUserRoles(ctx, iam.GroupByID(group.ID))
			noError(t, err)
			for _, r := range roles {
				if r.Email == email {
					return r.Role
				}
			}
			return iam.Role{}
		}
		code := func(err error) string {
			if e, ok := iam.AsError(err); ok {
				return e.Code()
			}
			return ""
		}

		t.Run("another_catalog", func(t *testing.T) {
			const email = "other-catalog@remote.example"
			peer := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) { c.Issuer = "https://other-catalog.example" }))
			id := invite(t, peer, email, f.reader)
			if _, err := f.auth.AcceptRemoteInvitation(ctx, remoteUser(t, f.auth, email), id); code(err) != "invitation_revoked" {
				t.Fatalf("an invitation of another application's catalog was redeemed: %v", err)
			}
			if got := holds(t, email); !got.IsZero() {
				t.Fatalf("refused invitation granted %s", got)
			}
		})

		t.Run("downgrade", func(t *testing.T) {
			const email = "remote-writer@remote.example"
			admin := invite(t, f.auth, email, f.writer)
			role, err := f.auth.AcceptRemoteInvitation(ctx, remoteUser(t, f.auth, email), admin)
			noError(t, err)
			if role != f.writer || holds(t, email) != f.writer {
				t.Fatalf("accepted %s, holds %s", role, holds(t, email))
			}
			// Single use, and a repeat by its holder is a no-op.
			role, err = f.auth.AcceptRemoteInvitation(ctx, remoteUser(t, f.auth, email), admin)
			if err != nil || role != f.writer {
				t.Fatalf("repeat acceptance by its holder: %s, %v", role, err)
			}
			member := invite(t, f.auth, email, f.reader)
			if _, err := f.auth.AcceptRemoteInvitation(ctx, remoteUser(t, f.auth, email), member); !errors.Is(err, iam.ErrRoleAssignmentEscalation) {
				t.Fatalf("a lower invitation replaced a remote writer's role: %v", err)
			}
			if got := holds(t, email); got != f.writer {
				t.Fatalf("remote writer now holds %s", got)
			}
		})

		t.Run("invitations_disabled", func(t *testing.T) {
			const email = "disabled@remote.example"
			id := invite(t, f.auth, email, f.reader)
			off := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) { unmountGroup(c, iam.RouteInvitations) }))
			if _, err := off.AcceptRemoteInvitation(ctx, remoteUser(t, off, email), id); !errors.Is(err, iam.ErrInvitationsDisabled) {
				t.Fatalf("an invitation was redeemed while invitations are disabled: %v", err)
			}
			if got := holds(t, email); !got.IsZero() {
				t.Fatalf("refused invitation granted %s", got)
			}
			// The switch refused it, not the invitation: it is still good.
			role, err := f.auth.AcceptRemoteInvitation(ctx, remoteUser(t, f.auth, email), id)
			if err != nil || role != f.reader {
				t.Fatalf("pending invitation after the refusal: %s, %v", role, err)
			}
		})
	})
}
