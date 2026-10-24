package critical_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func TestCriticalTenantAuthority(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J02-C01_public_identity_is_scoped_and_redacted", func(t *testing.T) {
		otherID := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherID}))
		other, err := f.auth.ForTenant(t.Context(), otherID)
		noError(t, err)
		in := iam.NewUser{Email: "shared-person@example.com", Username: "sharedperson", Password: authtest.Password, EmailVerified: true}
		a, err := f.auth.CreateUser(t.Context(), in)
		noError(t, err)
		b, err := other.CreateUser(t.Context(), in)
		noError(t, err)
		if a.ID == b.ID || a.TenantID != f.tenant || b.TenantID != otherID {
			t.Fatal("same identifier in two directories must produce distinct scoped accounts")
		}
		noError(t, f.auth.PatchPublicMetadata(t.Context(), iam.SystemIdentity(), a.ID, map[string]any{"avatar": "public-avatar"}))
		r := f.call(t, "GET", "/users?ids="+a.ID+","+b.ID, "", nil)
		r.want(t, http.StatusOK, "")
		var page struct {
			Data []map[string]json.RawMessage `json:"data"`
		}
		decode(t, r.body, &page)
		if len(page.Data) != 1 {
			t.Fatalf("public scope leaked or hid its valid control: %s", r.body)
		}
		var id, name string
		decode(t, page.Data[0]["id"], &id)
		decode(t, page.Data[0]["username"], &name)
		if id != a.ID || name != "sharedperson" {
			t.Fatalf("wrong public identity: %s", r.body)
		}
		allowed := map[string]bool{"id": true, "username": true, "created_at": true, "deleted": true, "public_metadata": true}
		for key := range page.Data[0] {
			if !allowed[key] {
				t.Fatalf("private field %q leaked in public projection", key)
			}
		}
		var metadata map[string]any
		decode(t, page.Data[0]["public_metadata"], &metadata)
		if metadata["avatar"] != "public-avatar" {
			t.Fatal("declared public metadata was incorrectly stripped")
		}
		lookup, err := other.User(t.Context(), iam.UserByEmail(in.Email))
		noError(t, err)
		if lookup.ID != b.ID {
			t.Fatal("trusted lookup escaped its selected tenant")
		}
	})
	t.Run("AK-J02-C02_bootstrap_replay_and_last_owner", func(t *testing.T) {
		manifest := iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: "genesisowner", Email: "genesis-owner@example.com", EmailVerified: true, Password: &iam.BootstrapUserPassword{Plaintext: authtest.Password}, RootRole: f.roles.Root.Owner}}}
		first, err := f.auth.ApplyBootstrapManifest(t.Context(), manifest, iam.BootstrapOptions{})
		noError(t, err)
		if first.UsersCreated != 1 {
			t.Fatalf("first bootstrap created %d users", first.UsersCreated)
		}
		user, err := f.auth.User(t.Context(), iam.UserByEmail("genesis-owner@example.com"))
		noError(t, err)
		second, err := f.auth.ApplyBootstrapManifest(t.Context(), manifest, iam.BootstrapOptions{})
		noError(t, err)
		if second.UsersCreated != 0 || second.UsersMatched != 1 {
			t.Fatalf("bootstrap replay did not converge: %+v", second)
		}
		err = f.auth.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(user.ID))
		if !errors.Is(err, iam.ErrLastOwner) {
			t.Fatalf("removing last root owner = %v", err)
		}
		roles, err := f.auth.GroupRoles(t.Context(), iam.RootGroup(), []iam.Subject{iam.UserSubject(user.ID)})
		noError(t, err)
		if roles[iam.UserSubject(user.ID)] != f.roles.Root.Owner {
			t.Fatal("refused removal changed owner role")
		}
	})
	t.Run("AK-J02-C03_rollback_leaves_no_user_or_event", func(t *testing.T) {
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(t.Context()) })
		in := iam.NewUser{Email: "rollback-person@example.com", Username: "rollbackperson", Password: authtest.Password, EmailVerified: true}
		user, err := f.auth.CreateUser(t.Context(), in, authkit.InTx(tx))
		noError(t, err)
		_, err = f.auth.User(t.Context(), iam.UserByID(user.ID))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("uncommitted user became visible: %v", err)
		}
		noError(t, tx.Rollback(t.Context()))
		_, err = f.auth.User(t.Context(), iam.UserByID(user.ID))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("rolled back user became visible: %v", err)
		}
		page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Limit: 500})
		noError(t, err)
		for _, event := range page.Events {
			if event.UserID == user.ID {
				t.Fatal("rolled back registration published an event")
			}
		}
		retried, err := f.auth.CreateUser(t.Context(), in)
		noError(t, err)
		got, err := f.auth.User(t.Context(), iam.UserByID(retried.ID))
		noError(t, err)
		if got.Username != in.Username {
			t.Fatal("retry did not commit the intended account")
		}
	})
	t.Run("AK-J02-C04_imported_contact_is_not_ownership_proof", func(t *testing.T) {
		result, err := f.auth.ImportUsers(t.Context(), []iam.ImportUser{{Email: "unproved-import@example.com", Username: "unprovedimport"}}, iam.ImportOptions{})
		noError(t, err)
		if result.Inserted != 1 {
			t.Fatalf("import result: %+v", result)
		}
		user, err := f.auth.User(t.Context(), iam.UserByEmail("unproved-import@example.com"))
		noError(t, err)
		if user.EmailVerified {
			t.Fatal("import fabricated contact verification")
		}
		_, err = f.auth.ApplyBootstrapManifest(t.Context(), iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Email: "unproved-import@example.com", Username: "unprovedimport", EmailVerified: true, RootRole: f.rootReader}}}, iam.BootstrapOptions{})
		if err == nil {
			t.Fatal("unproved imported contact was accepted as permission-granting proof")
		}
		roles, err := f.auth.GroupRoles(t.Context(), iam.RootGroup(), []iam.Subject{iam.UserSubject(user.ID)})
		noError(t, err)
		if !roles[iam.UserSubject(user.ID)].IsZero() {
			t.Fatal("refused bootstrap still granted root authority")
		}
	})
	t.Run("AK-J02-C05_borrowed_tenant_view_does_not_reidentify_actor", func(t *testing.T) {
		u := f.user(t)
		tokens := f.signIn(t, u)
		id := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		view, err := f.auth.ForTenant(t.Context(), id)
		noError(t, err)
		r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/source", nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		verified, err := f.auth.Authenticator().Authenticate(r)
		noError(t, err)
		actor, err := view.ResolveTenantActor(t.Context(), verified)
		noError(t, err)
		if actor.AccountID != u.ID || actor.TenantID != f.tenant {
			t.Fatal("target selection changed source identity")
		}
		otherServer := httptest.NewServer(view.Handler())
		t.Cleanup(otherServer.Close)
		otherFixture := &fixture{auth: view, server: otherServer}
		otherFixture.call(t, "GET", "/me", tokens.AccessToken, nil).want(t, http.StatusForbidden, "forbidden")
		if err := view.Start(t.Context()); err == nil {
			t.Fatal("borrowed view started the shared owner")
		}
		noError(t, view.Close(t.Context()))
		f.call(t, "GET", "/me", tokens.AccessToken, nil).want(t, http.StatusOK, "")
	})
}
