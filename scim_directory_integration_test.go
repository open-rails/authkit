package authkit_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/helpers/userinfo"
	"github.com/open-rails/helpers/userinfo/userinfotest"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/scim"
)

const (
	issuerA = "https://a.example.com"
	issuerC = "https://c.example.com"
)

// directoryService is AuthKit B: merchants whose groups hold API keys and
// remote applications, served over HTTP, with the paths it was asked for.
type directoryService struct {
	*authkit.Client
	URL                 string
	merchant            *authkit.PersonaDef
	provisioner, viewer iam.Role
	mu                  sync.Mutex
	paths               []string
}

func newDirectoryService(t *testing.T, opts ...authtest.Option) *directoryService {
	t.Helper()
	roles := authkit.NewRoles()
	merchant := roles.Persona("merchant", authkit.APIKeys, authkit.RemoteApplications)
	d := &directoryService{merchant: merchant,
		provisioner: merchant.Role("provisioner", merchant.Directory.All()),
		viewer:      merchant.Role("viewer", merchant.Directory.Read)}
	d.Client, _ = authtest.New(t, append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) { c.Roles = roles })}, opts...)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.paths = append(d.paths, r.Method+" "+r.URL.Path)
		d.mu.Unlock()
		d.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	d.URL = srv.URL + "/directory/scim/v2"
	return d
}

func (d *directoryService) asked(want string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.paths {
		if p == want {
			return true
		}
	}
	return false
}

// group is a new merchant group trusting issuer.
func (d *directoryService) group(t *testing.T, issuer string) (iam.GroupRef, iam.RemoteApplication) {
	t.Helper()
	g, err := d.CreateGroup(t.Context(), iam.NewGroup{Persona: d.merchant.Persona})
	require.NoError(t, err)
	ref := iam.GroupByID(g.ID)
	app, err := d.UpsertRemoteApplication(t.Context(), iam.SystemIdentity(), ref, iam.RemoteApplication{Issuer: issuer, JWKSURI: issuer + "/jwks.json", Enabled: true})
	require.NoError(t, err)
	return ref, app
}

// key is an API key of ref holding role, bound to the application provisions
// ("" for none).
func (d *directoryService) key(t *testing.T, ref iam.GroupRef, role iam.Role, provisions string) string {
	t.Helper()
	created, err := d.CreateAPIKey(t.Context(), iam.SystemIdentity(), ref, iam.NewAPIKey{Name: "scim", Role: role, ProvisionsFor: provisions})
	require.NoError(t, err)
	return created.Secret
}

// call sends method to the directory's path with token, a JSON body when
// body is not nil, and decodes a JSON answer into out.
func (d *directoryService) call(t *testing.T, token, method, path string, body, out any) (int, http.Header) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, d.URL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", scim.MediaType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		require.Equal(t, scim.MediaType, res.Header.Get("Content-Type"), "%s %s", method, path)
	}
	if out != nil && res.StatusCode != http.StatusNoContent {
		require.NoError(t, json.NewDecoder(res.Body).Decode(out))
	}
	return res.StatusCode, res.Header
}

// byExternalID is the directory's user whose externalId is subject.
func (d *directoryService) byExternalID(t *testing.T, token, subject string) (scim.User, bool) {
	t.Helper()
	var page scim.ListResponse[scim.User]
	status, _ := d.call(t, token, http.MethodGet, "/Users?filter="+url.QueryEscape(`externalId eq "`+subject+`"`), nil, &page)
	require.Equal(t, http.StatusOK, status)
	if page.TotalResults == 0 {
		return scim.User{}, false
	}
	require.Len(t, page.Resources, 1)
	return page.Resources[0], true
}

func patchOp(ops ...map[string]any) scim.PatchRequest {
	req := scim.PatchRequest{Schemas: []string{scim.SchemaPatchOp}}
	for _, op := range ops {
		value, _ := json.Marshal(op["value"])
		path, _ := op["path"].(string)
		req.Operations = append(req.Operations, scim.PatchOperation{Op: op["op"].(string), Path: path, Value: value})
	}
	return req
}

// TestDirectoryProvisioning: AuthKit A pushes its accounts through its real
// provisioning client to AuthKit B, into the directory of A's remote
// application in a merchant group. B's RemoteUserInfo serves them as A shows
// them now, and patches, deletions and SCIM's errors work; another group's
// credential reads and writes none of them.
func TestDirectoryProvisioning(t *testing.T) {
	b := newDirectoryService(t)
	ctx := t.Context()
	shop, appA := b.group(t, issuerA)
	other, appC := b.group(t, issuerC)
	push := b.key(t, shop, b.provisioner, appA.ID)

	a, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = issuerA
		c.Provisioning = authkit.ProvisioningConfig{Interval: time.Second, ReconcileInterval: -1,
			Targets: []authkit.ProvisioningTarget{{Name: "shop", URL: b.URL, BearerToken: push}}}
	}))
	alice, bob, carol := authtest.NewUser(t, a), authtest.NewUser(t, a), authtest.NewUser(t, a)
	require.NoError(t, a.Start(ctx))

	contacts := b.RemoteUserInfo(shop, issuerA)
	contact := func(u authtest.User) userinfo.User {
		return userinfo.User{ID: u.ID, Email: u.Email, Name: u.Username, Username: u.Username}
	}
	shows := func(want userinfo.User) {
		t.Helper()
		var got map[string]userinfo.User
		require.Eventually(t, func() bool {
			var err error
			got, err = contacts.Get(ctx, []string{want.ID})
			require.NoError(t, err)
			return got[want.ID] == want
		}, 30*time.Second, 100*time.Millisecond, "B never showed %+v; it holds %+v", want, got)
	}
	absent := func(id string) {
		t.Helper()
		require.Eventually(t, func() bool {
			got, err := contacts.Get(ctx, []string{id})
			require.NoError(t, err)
			return len(got) == 0
		}, 30*time.Second, 100*time.Millisecond, "B still shows %s", id)
	}
	for _, u := range []authtest.User{alice, bob, carol} {
		shows(contact(u))
	}
	require.True(t, b.asked(http.MethodPost+" /directory/scim/v2/Bulk"), "A pushes in bulk, as B advertises")

	t.Run("RemoteUserInfo is a userinfo.Lookup of what A shows now", func(t *testing.T) {
		userinfotest.Check(t, contacts, userinfotest.Fixtures{
			Users:   []userinfo.User{contact(alice), contact(bob)},
			Unknown: []string{"0192f6a0-0000-7000-8000-00000000c0de"},
			Change: func(c userinfo.User) userinfo.User {
				email, name, verified := "changed-"+c.Email, "changed"+c.ID[len(c.ID)-8:], true
				_, err := a.UpdateUser(ctx, iam.SystemIdentity(), c.ID, iam.UserUpdate{Email: &email, Username: &name, EmailVerified: &verified})
				require.NoError(t, err)
				now := userinfo.User{ID: c.ID, Email: email, Name: name, Username: name}
				shows(now)
				return now
			},
		})
	})

	t.Run("an address A has not verified is not pushed", func(t *testing.T) {
		unproven := "unproven-" + alice.Email
		_, err := a.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{Email: &unproven})
		require.NoError(t, err)
		shows(userinfo.User{ID: alice.ID, Name: alice.Username, Username: alice.Username})
	})

	t.Run("filters, patches and SCIM's errors", func(t *testing.T) {
		u, ok := b.byExternalID(t, push, alice.ID)
		require.True(t, ok)
		var page scim.ListResponse[scim.User]
		status, _ := b.call(t, push, http.MethodGet, "/Users?filter="+url.QueryEscape(`userName eq "`+alice.Username+`"`), nil, &page)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, page.TotalResults)
		require.Equal(t, u.ID, page.Resources[0].ID)
		status, _ = b.call(t, push, http.MethodGet, "/Users?filter="+url.QueryEscape(`nickName eq "x"`), nil, nil)
		require.Equal(t, http.StatusBadRequest, status)

		// Microsoft Entra ID's shapes: capitalized ops, a value filter, a
		// boolean as a string.
		var got scim.User
		status, _ = b.call(t, push, http.MethodPatch, "/Users/"+u.ID, patchOp(
			map[string]any{"op": "Replace", "path": "displayName", "value": "Alice Liddell"},
			map[string]any{"op": "Add", "path": `emails[type eq "work"].value`, "value": "alice@work.example"},
			map[string]any{"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Sales"},
		), &got)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "Alice Liddell", got.DisplayName)
		require.Equal(t, []scim.Email{{Value: "alice@work.example", Type: "work", Primary: true}}, got.Emails)
		shows(userinfo.User{ID: alice.ID, Email: "alice@work.example", Name: "Alice Liddell", Username: alice.Username})

		status, _ = b.call(t, push, http.MethodPatch, "/Users/"+u.ID, patchOp(map[string]any{"op": "Replace", "path": "active", "value": "False"}), &got)
		require.Equal(t, http.StatusOK, status)
		require.False(t, *got.Active)
		absent(alice.ID)
		// Okta's shape: no path, the attributes as the value.
		status, _ = b.call(t, push, http.MethodPatch, "/Users/"+u.ID, patchOp(map[string]any{"op": "replace", "value": map[string]any{"active": true}}), &got)
		require.Equal(t, http.StatusOK, status)
		shows(userinfo.User{ID: alice.ID, Email: "alice@work.example", Name: "Alice Liddell", Username: alice.Username})

		for _, c := range []struct {
			req      scim.PatchRequest
			scimType string
		}{
			{patchOp(map[string]any{"op": "remove", "path": "userName"}), "invalidValue"},
			{patchOp(map[string]any{"op": "remove", "path": "externalId"}), "invalidValue"},
			{patchOp(map[string]any{"op": "replace", "path": "name[given eq"}), "invalidPath"},
			{patchOp(map[string]any{"op": "replace", "path": `emails[type eq "home"].value`, "value": "x@home.example"}), "noTarget"},
			{patchOp(map[string]any{"op": "remove"}), "noTarget"},
			{patchOp(map[string]any{"op": "move", "path": "displayName", "value": "x"}), "invalidSyntax"},
			{patchOp(map[string]any{"op": "replace", "path": "id", "value": "other"}), "mutability"},
			{scim.PatchRequest{Operations: patchOp(map[string]any{"op": "replace", "path": "displayName", "value": "x"}).Operations}, "invalidSyntax"},
		} {
			var e scim.Error
			status, _ := b.call(t, push, http.MethodPatch, "/Users/"+u.ID, c.req, &e)
			require.Equal(t, http.StatusBadRequest, status, "%+v", c.req)
			require.Equal(t, c.scimType, e.ScimType, "%+v: %s", c.req, e.Detail)
			require.Equal(t, []string{scim.SchemaError}, e.Schemas)
			require.Equal(t, "400", e.Status)
		}

		var e scim.Error
		dup := scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: alice.ID, UserName: "someone-else"}
		status, _ = b.call(t, push, http.MethodPost, "/Users", dup, &e)
		require.Equal(t, http.StatusConflict, status)
		require.Equal(t, "uniqueness", e.ScimType)
		dup = scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: "0192f6a0-0000-7000-8000-0000000000aa", UserName: alice.Username}
		status, _ = b.call(t, push, http.MethodPost, "/Users", dup, &e)
		require.Equal(t, http.StatusConflict, status, "userName is unique among the issuer's users")
		require.Equal(t, "uniqueness", e.ScimType)
		status, _ = b.call(t, push, http.MethodPost, "/Users", scim.User{Schemas: []string{scim.SchemaUser}, UserName: "no-subject"}, &e)
		require.Equal(t, http.StatusBadRequest, status, "externalId is the subject and required")
		require.Equal(t, "invalidValue", e.ScimType)
		status, _ = b.call(t, push, http.MethodGet, "/Users/0192f6a0-0000-7000-8000-00000000c0de", nil, &e)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("a deletion at A deactivates, then its purge deletes", func(t *testing.T) {
		_, err := a.DeleteUsers(ctx, iam.SystemIdentity(), []string{carol.ID})
		require.NoError(t, err)
		absent(carol.ID)
		_, ok := b.byExternalID(t, push, carol.ID)
		require.True(t, ok, "a deleted account is inactive within its 30 days")
		res, err := a.PurgeUsers(ctx, []string{carol.ID})
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
		require.Eventually(t, func() bool { _, ok := b.byExternalID(t, push, carol.ID); return !ok }, 30*time.Second, 100*time.Millisecond)
	})

	t.Run("a SCIM DELETE deletes the user", func(t *testing.T) {
		u := scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: "0192f6a0-0000-7000-8000-0000000000dd", UserName: "dora",
			Emails: []scim.Email{{Value: "dora@example.com"}}}
		var created scim.User
		status, header := b.call(t, push, http.MethodPost, "/Users", u, &created)
		require.Equal(t, http.StatusCreated, status)
		require.Equal(t, created.Meta.Location, header.Get("Location"))
		require.NotNil(t, created.Meta.Created)
		shows(userinfo.User{ID: u.ExternalID, Email: "dora@example.com", Name: "", Username: "dora"})
		status, _ = b.call(t, push, http.MethodDelete, "/Users/"+created.ID, nil, nil)
		require.Equal(t, http.StatusNoContent, status)
		absent(u.ExternalID)
		status, _ = b.call(t, push, http.MethodDelete, "/Users/"+created.ID, nil, nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("credentials", func(t *testing.T) {
		u, ok := b.byExternalID(t, push, bob.ID)
		require.True(t, ok)
		var e scim.Error
		status, header := b.call(t, "", http.MethodGet, "/Users/"+u.ID, nil, &e)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "Bearer", header.Get("WWW-Authenticate"))
		status, header = b.call(t, "not-a-key", http.MethodGet, "/Users/"+u.ID, nil, &e)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Contains(t, header.Get("WWW-Authenticate"), `error="invalid_token"`)

		unbound := b.key(t, shop, b.provisioner, "")
		status, _ = b.call(t, unbound, http.MethodGet, "/Users/"+u.ID, nil, &e)
		require.Equal(t, http.StatusForbidden, status, "a key provisions only the application it is bound to")

		viewer := b.key(t, shop, b.viewer, appA.ID)
		status, _ = b.call(t, viewer, http.MethodGet, "/Users/"+u.ID, nil, nil)
		require.Equal(t, http.StatusOK, status)
		status, header = b.call(t, viewer, http.MethodPatch, "/Users/"+u.ID, patchOp(map[string]any{"op": "replace", "path": "displayName", "value": "x"}), &e)
		require.Equal(t, http.StatusForbidden, status, "writing takes merchant:directory:manage")
		require.Contains(t, header.Get("WWW-Authenticate"), `error="insufficient_scope"`)

		_, err := b.CreateAPIKey(ctx, iam.SystemIdentity(), shop, iam.NewAPIKey{Name: "x", Role: b.provisioner, ProvisionsFor: appC.ID})
		require.ErrorIs(t, err, iam.ErrRemoteApplicationNotFound, "a key is bound only to its own group's application")

		disabled := appA
		disabled.Enabled = false
		_, err = b.UpsertRemoteApplication(ctx, iam.SystemIdentity(), shop, disabled)
		require.NoError(t, err)
		status, _ = b.call(t, push, http.MethodGet, "/Users/"+u.ID, nil, &e)
		require.Equal(t, http.StatusForbidden, status, "a disabled application provisions nothing")
		_, err = b.UpsertRemoteApplication(ctx, iam.SystemIdentity(), shop, appA)
		require.NoError(t, err)
	})

	t.Run("another group's credential reads and writes none of it", func(t *testing.T) {
		u, ok := b.byExternalID(t, push, bob.ID)
		require.True(t, ok)
		stranger := b.key(t, other, b.provisioner, appC.ID)
		var page scim.ListResponse[scim.User]
		status, _ := b.call(t, stranger, http.MethodGet, "/Users", nil, &page)
		require.Equal(t, http.StatusOK, status)
		require.Zero(t, page.TotalResults)
		_, found := b.byExternalID(t, stranger, bob.ID)
		require.False(t, found)
		replace := scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: bob.ID, UserName: "taken"}
		for _, c := range []struct {
			method string
			body   any
		}{
			{http.MethodGet, nil}, {http.MethodPut, replace},
			{http.MethodPatch, patchOp(map[string]any{"op": "replace", "path": "displayName", "value": "x"})}, {http.MethodDelete, nil},
		} {
			status, _ := b.call(t, stranger, c.method, "/Users/"+u.ID, c.body, nil)
			require.Equal(t, http.StatusNotFound, status, c.method)
		}
		var bulk scim.BulkResponse
		status, _ = b.call(t, stranger, http.MethodPost, "/Bulk", scim.BulkRequest{Schemas: []string{scim.SchemaBulkRequest},
			Operations: []scim.BulkOperation{{Method: http.MethodDelete, Path: "/Users/" + u.ID}}}, &bulk)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, scim.Status(http.StatusNotFound), bulk.Operations[0].Status)

		got, err := b.RemoteUserInfo(other, issuerA).Get(ctx, []string{bob.ID})
		require.NoError(t, err)
		require.Empty(t, got, "the directory is the group's")
		got, err = b.RemoteUserInfo(shop, issuerC).Get(ctx, []string{bob.ID})
		require.NoError(t, err)
		require.Empty(t, got, "and the issuer's")
		_, ok = b.byExternalID(t, push, bob.ID)
		require.True(t, ok, "bob is untouched")
	})

	t.Run("discovery", func(t *testing.T) {
		var spc scim.ServiceProviderConfig
		status, _ := b.call(t, "", http.MethodGet, "/ServiceProviderConfig", nil, &spc)
		require.Equal(t, http.StatusOK, status)
		require.True(t, spc.Patch.Supported)
		require.True(t, spc.Bulk.Supported)
		require.True(t, spc.Filter.Supported)
		var schema scim.SchemaDoc
		status, _ = b.call(t, "", http.MethodGet, "/Schemas/"+url.PathEscape(scim.SchemaUser), nil, &schema)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "readWrite", schema.Attributes[0].Mutability)
		var types scim.ListResponse[scim.ResourceType]
		status, _ = b.call(t, "", http.MethodGet, "/ResourceTypes", nil, &types)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "/Users", types.Resources[0].Endpoint)
	})

	targets, err := a.ProvisioningTargets(ctx)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Nil(t, targets[0].FailingSince, "A's pushes all landed: %v", targets[0].LastError)
}
