package critical_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/provider"
)

// An identity-only adapter preserves the original provider's sealed state.
type actorIdentityOnly struct{ id auth.Identity }

func (v actorIdentityOnly) Identity() auth.Identity { return v.id }

func TestCriticalTenantAuthority(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J02-C01_public_identity_is_scoped_and_redacted", func(t *testing.T) {
		otherID := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherID, Slug: "scoped-other"}))
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
		_, err = f.auth.EnsureUserRole(t.Context(), iam.RootGroup(), iam.UserByEmail("unproved-import@example.com"), f.rootReader)
		if !errors.Is(err, iam.ErrContactNotVerified) {
			t.Fatalf("EnsureUserRole adopted an unproved contact: %v", err)
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
		verified := f.user(t)
		ensured, err := f.auth.EnsureUserRole(t.Context(), iam.RootGroup(), iam.UserByEmail(verified.Email), f.rootReader)
		noError(t, err)
		if ensured.ID != verified.ID {
			t.Fatal("verified contact provisioning reidentified the user")
		}
		ensured, err = f.auth.EnsureUserRole(t.Context(), iam.RootGroup(), iam.UserByEmail(verified.Email), f.rootReader)
		noError(t, err)
		if ensured.ID != verified.ID {
			t.Fatal("replayed provisioning did not converge")
		}
		link := iam.ProviderLink{Issuer: "https://legacy-idp.example", Subject: "legacy-subject", Provider: "legacy", Email: verified.Email}
		noError(t, f.auth.LinkProvider(t.Context(), verified.ID, link))
		noError(t, f.auth.LinkProvider(t.Context(), verified.ID, link))
		if err := f.auth.LinkProvider(t.Context(), user.ID, link); err == nil {
			t.Fatal("trusted import moved an already-linked external identity to another user")
		}
		wallets, err := f.auth.ImportSolanaLinks(t.Context(), []iam.ImportSolanaLink{{UserID: verified.ID, Address: "11111111111111111111111111111111", Source: "legacy", SourceID: "reserved-wallet"}})
		noError(t, err)
		if wallets.Inserted != 1 {
			t.Fatalf("wallet reservation import:%+v", wallets)
		}
		conflict, err := f.auth.ImportSolanaLinks(t.Context(), []iam.ImportSolanaLink{{UserID: user.ID, Address: "11111111111111111111111111111111", Source: "legacy", SourceID: "reserved-wallet"}})
		noError(t, err)
		if conflict.Rejected != 1 {
			t.Fatal("legacy wallet reservation was reassigned to another account")
		}
	})
	t.Run("AK-J02-C05_borrowed_tenant_view_does_not_reidentify_actor", func(t *testing.T) {
		u := f.user(t)
		tokens := f.signIn(t, u)
		id := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: id, Slug: "borrowed-view"}))
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
		for _, invalid := range []auth.Verified{nil, actorIdentityOnly{}} {
			actor, err := view.ResolveTenantActor(t.Context(), invalid)
			if err == nil || actor != (iam.TenantActor{}) {
				t.Fatalf("identity without verified lifetime resolved an actor: %+v, %v", actor, err)
			}
		}
		forwarded, err := view.ResolveTenantActor(t.Context(), actorIdentityOnly{verified.Identity()})
		noError(t, err)
		if forwarded != actor {
			t.Fatalf("identity-preserving adapter changed native source account: %+v", forwarded)
		}
		foreign := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Token.Issuer = "https://different-actor-issuer.example"
		}))
		foreignUser := foreign.user(t)
		foreignTokens := foreign.signIn(t, foreignUser)
		foreignRequest, err := http.NewRequestWithContext(t.Context(), "GET", foreign.server.URL+"/source", nil)
		noError(t, err)
		foreignRequest.Header.Set("Authorization", "Bearer "+foreignTokens.AccessToken)
		foreignVerified, err := foreign.auth.Authenticator().Authenticate(foreignRequest)
		noError(t, err)
		if actor, err := view.ResolveTenantActor(t.Context(), foreignVerified); !errors.Is(err, auth.ErrForbidden) || actor != (iam.TenantActor{}) {
			t.Fatalf("foreign verified credential acquired native actor authority: %+v, %v", actor, err)
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
		_, err = f.auth.RevokeAccountSessions(t.Context(), iam.UserIdentity(u.ID), u.ID)
		noError(t, err)
		if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
			t.Fatalf("revoked credential retained source-account authority: %+v, %v", actor, err)
		}
	})
}

func TestCriticalProviderReconciliation(t *testing.T) {
	idp := authtest.NewIdP(t)
	otherIDP := authtest.NewIdP(t)
	first, second := idp.Provider("first"), otherIDP.Provider("second")
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.PasswordlessLogin = false
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.Providers = []provider.Provider{first, second}
	}))
	link := iam.ProviderLink{Issuer: first.Issuer(), Provider: first.Name(), Subject: "original", Email: "original@example.com"}
	other := iam.ProviderLink{Issuer: second.Issuer(), Provider: second.Name(), Subject: "other"}
	state := func(userID, issuer string) string {
		t.Helper()
		var value string
		noError(t, f.pool.QueryRow(t.Context(), `SELECT COALESCE((SELECT row_to_json(p)::text FROM `+pgx.Identifier{f.schema, "user_providers"}.Sanitize()+` p WHERE user_id=$1 AND issuer=$2), '')`, userID, issuer).Scan(&value))
		return value
	}
	t.Run("unlink_replace_retry_expectation_and_other_issuers", func(t *testing.T) {
		u := f.user(t)
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, link))
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, other))
		initial, unrelated := state(u.ID, link.Issuer), state(u.ID, other.Issuer)
		desired := link
		desired.Subject, desired.Email = "replacement", "replacement@example.com"
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, "stale", desired); !errors.Is(err, iam.ErrProviderSubjectMismatch) {
			t.Fatalf("stale expectation = %v", err)
		}
		if state(u.ID, link.Issuer) != initial {
			t.Fatal("refused reconciliation changed state")
		}
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, link.Subject, desired))
		replaced := state(u.ID, link.Issuer)
		var stored struct{ Subject, EmailAtProvider string }
		noError(t, f.pool.QueryRow(t.Context(), `SELECT subject,email_at_provider FROM `+pgx.Identifier{f.schema, "user_providers"}.Sanitize()+` WHERE user_id=$1 AND issuer=$2`, u.ID, link.Issuer).Scan(&stored.Subject, &stored.EmailAtProvider))
		if stored.Subject != desired.Subject || stored.EmailAtProvider != desired.Email {
			t.Fatalf("replacement not applied: %+v", stored)
		}
		desired.Email = "must-not-write@example.com"
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, link.Subject, desired))
		if state(u.ID, link.Issuer) != replaced {
			t.Fatal("retry wrote metadata")
		}
		desired.Subject = ""
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, "replacement", desired))
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, "replacement", desired))
		if state(u.ID, link.Issuer) != "" || state(u.ID, other.Issuer) != unrelated {
			t.Fatal("unlink failed or touched another issuer")
		}
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, "", link))
		if state(u.ID, link.Issuer) == "" {
			t.Fatal("reconciliation from absent did not link")
		}
	})
	t.Run("occupied_identity_rolls_back_replace", func(t *testing.T) {
		u, owner := f.user(t), f.user(t)
		occupied := link
		occupied.Subject = "occupied"
		noError(t, f.auth.LinkProvider(t.Context(), owner.ID, occupied))
		current := link
		current.Subject = "rollback-original"
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, current))
		before, held := state(u.ID, link.Issuer), state(owner.ID, link.Issuer)
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, current.Subject, occupied); !errors.Is(err, iam.ErrProviderAlreadyLinked) {
			t.Fatalf("occupied identity = %v", err)
		}
		if state(u.ID, link.Issuer) != before || state(owner.ID, link.Issuer) != held {
			t.Fatal("failed replace lost a link")
		}
	})
	t.Run("last_method_and_atomic_replacement", func(t *testing.T) {
		u, err := f.auth.CreateUser(t.Context(), iam.NewUser{Username: "provideronly", Email: "provideronly@example.com", EmailVerified: true})
		noError(t, err)
		sole := link
		sole.Subject = "sole-original"
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, sole))
		remove := sole
		remove.Subject = ""
		before := state(u.ID, sole.Issuer)
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, sole.Subject, remove); !errors.Is(err, iam.ErrCannotUnlinkLastLoginMethod) {
			t.Fatalf("last sign-in method = %v", err)
		}
		if state(u.ID, sole.Issuer) != before {
			t.Fatal("refused last-method removal changed state")
		}
		next := sole
		next.Subject = "sole-replacement"
		unusable := next
		unusable.Provider = "disabled"
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, sole.Subject, unusable); !errors.Is(err, iam.ErrCannotUnlinkLastLoginMethod) {
			t.Fatalf("replacement without a usable sign-in method = %v", err)
		}
		if state(u.ID, sole.Issuer) != before {
			t.Fatal("refused replacement changed the sole link")
		}
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, sole.Subject, next))
		// A second configured issuer is sufficient even without a password.
		another := other
		another.Subject = "sole-other"
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, another))
		noError(t, f.auth.ReconcileProvider(t.Context(), u.ID, next.Subject, remove))
		if state(u.ID, another.Issuer) == "" {
			t.Fatal("last-method check removed the remaining issuer")
		}
	})
	t.Run("concurrent_replacements_compare_under_the_account_lock", func(t *testing.T) {
		u := f.user(t)
		old := link
		old.Subject = "race-original"
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, old))
		start, done := make(chan struct{}), make(chan error, 2)
		for _, subject := range []string{"race-a", "race-b"} {
			go func() {
				<-start
				next := link
				next.Subject = subject
				done <- f.auth.ReconcileProvider(t.Context(), u.ID, old.Subject, next)
			}()
		}
		close(start)
		wins, conflicts := 0, 0
		for range 2 {
			switch err := <-done; {
			case err == nil:
				wins++
			case errors.Is(err, iam.ErrProviderSubjectMismatch):
				conflicts++
			default:
				t.Fatalf("concurrent replace = %v", err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("race: wins=%d conflicts=%d", wins, conflicts)
		}
	})
	t.Run("concurrent_unlinks_preserve_a_last_method", func(t *testing.T) {
		u, err := f.auth.CreateUser(t.Context(), iam.NewUser{Username: "unlinkrace", Email: "unlinkrace@example.com", EmailVerified: true})
		noError(t, err)
		a, b := link, other
		a.Subject, b.Subject = "unlink-race-a", "unlink-race-b"
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, a))
		noError(t, f.auth.LinkProvider(t.Context(), u.ID, b))
		start, done := make(chan struct{}), make(chan error, 2)
		for _, l := range []iam.ProviderLink{a, b} {
			go func() {
				<-start
				expected := l.Subject
				l.Subject = ""
				done <- f.auth.ReconcileProvider(t.Context(), u.ID, expected, l)
			}()
		}
		close(start)
		wins, refusals := 0, 0
		for range 2 {
			switch err := <-done; {
			case err == nil:
				wins++
			case errors.Is(err, iam.ErrCannotUnlinkLastLoginMethod):
				refusals++
			default:
				t.Fatalf("concurrent unlink = %v", err)
			}
		}
		if wins != 1 || refusals != 1 || (state(u.ID, a.Issuer) == "") == (state(u.ID, b.Issuer) == "") {
			t.Fatal("concurrent unlinks did not retain exactly one sign-in method")
		}
	})

	t.Run("tenant_deleted_options_and_invalid_inputs", func(t *testing.T) {
		u := f.user(t)
		otherTenant := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherTenant, Slug: "provider-other"}))
		view, err := f.auth.ForTenant(t.Context(), otherTenant)
		noError(t, err)
		if err := view.ReconcileProvider(t.Context(), u.ID, "", link); !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("cross-tenant reconcile = %v", err)
		}
		if err := f.auth.ReconcileProvider(t.Context(), "invalid", "", link); !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("invalid account = %v", err)
		}
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, "", iam.ProviderLink{}); err == nil {
			t.Fatal("empty issuer accepted")
		}
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, "", link, authkit.IncludeDeleted()); err == nil {
			t.Fatal("unsupported option accepted")
		}
		results, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		noError(t, err)
		noError(t, results[0].Err)
		if err := f.auth.ReconcileProvider(t.Context(), u.ID, "", link); !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("deleted target = %v", err)
		}
		if state(u.ID, link.Issuer) != "" {
			t.Fatal("refused target gained a provider link")
		}
	})
}
