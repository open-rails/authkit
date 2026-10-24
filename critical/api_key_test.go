package critical_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// This creator signs in through the real HTTP flow; keys are issued through
// the actual public authority operation, not inserted into test tables.
func (f *fixture) key(t *testing.T) (iam.APIKeyCreated, iam.Group, auth.Identity) {
	t.Helper()
	u := f.user(t)
	token := f.signIn(t, u)
	who := f.identity(t, token.AccessToken)
	subject := iam.UserSubject(u.ID)
	g, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: f.shop.Persona, Owner: &subject})
	noError(t, err)
	k, err := f.auth.CreateAPIKey(t.Context(), who, iam.GroupByID(g.ID), iam.NewAPIKey{Name: "critical worker", Role: f.reader})
	noError(t, err)
	return k, g, who
}

func (f *fixture) authenticate(t *testing.T, credential string) (auth.Verified, error) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/resource", nil)
	noError(t, err)
	r.Header.Set("Authorization", "Bearer "+credential)
	return f.auth.Authenticator().Authenticate(r)
}

func TestCriticalAPIKeyAuthority(t *testing.T) {
	t.Run("AK-J16-C01_real_key_lifecycle_and_credential_error_classes", func(t *testing.T) {
		f := newFixture(t)
		key, group, who := f.key(t)
		v, err := f.authenticate(t, key.Secret)
		noError(t, err)
		if v.Identity().Subject != group.ID {
			t.Fatal("group key acted as its creator instead of the group")
		}
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(group.ID))
		noError(t, err)
		checker, ok := v.(auth.PermissionChecker)
		if !ok {
			t.Fatal("real key omitted permission checker")
		}
		allowed, err := checker.Can(t.Context(), scope, f.read.String())
		noError(t, err)
		if !allowed {
			t.Fatal("valid key lost its intended read grant")
		}
		allowed, err = checker.Can(t.Context(), scope, f.write.String())
		noError(t, err)
		if allowed {
			t.Fatal("read-only key acquired a write grant")
		}
		page, err := f.auth.ListAPIKeys(t.Context(), iam.GroupByID(group.ID), iam.PageRequest{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].ID != key.APIKey.ID {
			t.Fatal("key metadata did not read back")
		}
		unknownID := "a" + key.APIKey.LookupID[1:]
		if unknownID == key.APIKey.LookupID {
			unknownID = "b" + key.APIKey.LookupID[1:]
		}
		unknown := strings.Replace(key.Secret, key.APIKey.LookupID, unknownID, 1)
		if unknown == key.Secret {
			t.Fatal("fixture did not change the key lookup identifier")
		}
		_, err = f.authenticate(t, unknown)
		if !errors.Is(err, auth.ErrUnauthenticated) || auth.Refuse(nil, err).Status != http.StatusUnauthorized || errors.Is(err, auth.ErrUnavailable) {
			t.Fatalf("unknown key classification=%v", err)
		}
		noError(t, f.auth.RevokeAPIKey(t.Context(), who, iam.GroupByID(group.ID), key.APIKey.ID))
		_, err = f.authenticate(t, key.Secret)
		if !errors.Is(err, auth.ErrRevoked) || auth.Refuse(nil, err).Status != http.StatusUnauthorized {
			t.Fatalf("revoked key classification=%v", err)
		}
		expiredFixture := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.APIKeys.MaxTTL = time.Nanosecond }))
		expired, _, _ := expiredFixture.key(t)
		if expired.APIKey.ExpiresAt == nil || !expired.APIKey.ExpiresAt.Before(time.Now()) {
			t.Fatal("fixture key has not reached its returned expiration boundary")
		}
		_, err = expiredFixture.authenticate(t, expired.Secret)
		if !errors.Is(err, auth.ErrExpired) || auth.Refuse(nil, err).Status != http.StatusUnauthorized {
			t.Fatalf("expired key classification=%v", err)
		}
	})
	t.Run("AK-J31-C06_database_outage_is_unavailable_not_bad_credentials", func(t *testing.T) {
		u, err := url.Parse(os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
		noError(t, err)
		link := newDatabaseLink(t, u.Host)
		u.Host = link.listener.Addr().String()
		query := u.Query()
		query.Set("connect_timeout", "1")
		u.RawQuery = query.Encode()
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			pool, err := pgxpool.New(t.Context(), u.String())
			noError(t, err)
			t.Cleanup(pool.Close)
			d.Postgres = pool
		}))
		key, group, _ := f.key(t)
		v, err := f.authenticate(t, key.Secret)
		noError(t, err)
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(group.ID))
		noError(t, err)
		can, err := v.(auth.PermissionChecker).Can(t.Context(), scope, f.read.String())
		noError(t, err)
		if !can {
			t.Fatal("positive control lacks authority before network failure")
		}
		link.cut()
		_, err = f.authenticate(t, key.Secret)
		if !errors.Is(err, auth.ErrUnavailable) || errors.Is(err, auth.ErrUnauthenticated) || auth.Refuse(nil, err).Status != http.StatusServiceUnavailable {
			t.Fatalf("storage outage misclassified as credential rejection: %v", err)
		}
		// The host's independent database connection is still healthy. The
		// fixture interrupted AuthKit's actual transport, not the whole server.
		noError(t, f.pool.Ping(t.Context()))
	})
	t.Run("AK-J16-C02_key_is_bound_to_its_group_and_issuing_app", func(t *testing.T) {
		f := newFixture(t)
		key, group, _ := f.key(t)
		other, _, _ := f.ownedGroup(t)
		v, err := f.authenticate(t, key.Secret)
		noError(t, err)
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(other.ID))
		noError(t, err)
		allowed, err := v.(auth.PermissionChecker).Can(t.Context(), scope, f.read.String())
		noError(t, err)
		if allowed {
			t.Fatal("key crossed into another group's authority")
		}
		bound, ok := v.(auth.Bound)
		if !ok || bound.BoundScope().ID != group.ID || bound.BoundScope().Authority != authtest.Issuer {
			t.Fatal("key did not expose its immutable issuer/group bound scope")
		}
		peer := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) { c.Token.Issuer = "https://other-app.example" }))
		r, err := http.NewRequestWithContext(t.Context(), "GET", "https://other-app.example/resource", nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+key.Secret)
		if _, err := peer.Authenticator().Authenticate(r); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("same database different issuer accepted key: %v", err)
		}
	})
	t.Run("AK-J16-C03_issuer_cannot_grant_above_its_current_authority", func(t *testing.T) {
		f := newFixture(t)
		group, _, owner := f.ownedGroup(t)
		ref := iam.GroupByID(group.ID)
		issuer := f.user(t)
		role, err := f.auth.CreateGroupRole(t.Context(), owner, ref, iam.NewGroupRole{Name: "keyissuer", Permissions: []iam.Perm{f.read, f.shop.Credentials.Read, f.shop.Credentials.Manage}})
		noError(t, err)
		f.grant(t, group, issuer, role.Name)
		who := f.identity(t, f.signIn(t, issuer).AccessToken)
		_, err = f.auth.CreateAPIKey(t.Context(), who, ref, iam.NewAPIKey{Name: "allowed read", Role: f.reader})
		noError(t, err)
		_, err = f.auth.CreateAPIKey(t.Context(), who, ref, iam.NewAPIKey{Name: "forbidden owner", Role: f.shop.Owner})
		if !errors.Is(err, iam.ErrRoleAssignmentEscalation) {
			t.Fatalf("key issuer widened its authority: %v", err)
		}
		keys, err := f.auth.ListAPIKeys(t.Context(), ref, iam.PageRequest{})
		noError(t, err)
		if len(keys.Items) != 1 || keys.Items[0].Role != f.reader {
			t.Fatal("refused key issuance left a stronger credential behind")
		}
	})
	t.Run("AK-J16-C04_group_key_survives_creator_departure_but_not_removed_role", func(t *testing.T) {
		f := newFixture(t)
		noError(t, f.auth.Start(context.Background()))
		key, group, creator := f.key(t)
		ref := iam.GroupByID(group.ID)
		replacement := f.user(t)
		f.grant(t, group, replacement, f.shop.Owner)
		noError(t, f.auth.RemoveGroupMember(t.Context(), iam.SystemIdentity(), ref, iam.UserSubject(creator.Subject)))
		_, err := f.authenticate(t, key.Secret)
		noError(t, err)
		deleted, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{creator.Subject})
		noError(t, err)
		if len(deleted) != 1 || deleted[0].Err != nil {
			t.Fatalf("creator deletion: %+v", deleted)
		}
		_, err = f.authenticate(t, key.Secret)
		noError(t, err)
		role, err := f.auth.CreateGroupRole(t.Context(), iam.SystemIdentity(), ref, iam.NewGroupRole{Name: "retirable", Permissions: []iam.Perm{f.read}})
		noError(t, err)
		retired, err := f.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), ref, iam.NewAPIKey{Name: "role lifecycle", Role: role.Name})
		noError(t, err)
		noError(t, f.auth.DeleteGroupRole(t.Context(), iam.SystemIdentity(), ref, role.Name))
		_, err = f.auth.CreateGroupRole(t.Context(), iam.SystemIdentity(), ref, iam.NewGroupRole{Name: "retirable", Permissions: []iam.Perm{f.read}})
		noError(t, err)
		_, err = f.authenticate(t, retired.Secret)
		if !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("recreated role revived retired credential: %v", err)
		}
	})
	t.Run("AK-J16-C05_key_secret_is_not_read_back_and_revoke_is_repeatable", func(t *testing.T) {
		f := newFixture(t)
		key, group, owner := f.key(t)
		token, err := f.auth.MintAccessToken(t.Context(), owner.Subject, iam.AccessTokenOptions{SessionID: owner.Credential.ID})
		noError(t, err)
		path := "/groups/" + group.ID + "/api-keys"
		r := f.call(t, "GET", path, token.Value, nil)
		r.want(t, http.StatusOK, "")
		var page struct {
			Data []map[string]json.RawMessage `json:"data"`
		}
		decode(t, r.body, &page)
		if len(page.Data) != 1 {
			t.Fatal("key listing lost the valid control")
		}
		for _, name := range []string{"secret", "secret_hash", "token"} {
			if _, exists := page.Data[0][name]; exists {
				t.Fatalf("key listing exposed %s", name)
			}
		}
		if strings.Contains(string(r.body), key.Secret) {
			t.Fatal("key listing exposed the issued secret")
		}
		for range 2 {
			f.call(t, "DELETE", path+"/"+key.APIKey.ID, token.Value, nil).want(t, http.StatusNoContent, "")
		}
		_, err = f.authenticate(t, key.Secret)
		if !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("repeated revocation changed the terminal state: %v", err)
		}
	})
}
