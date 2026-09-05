package authhttp

// #264 end-to-end: application self-registration over the mounted HTTP
// surface against a real Postgres + a live (loopback) application.json
// server. Covers the whole doctrine: domain-proof registration with a
// service-owned org, idempotent re-registration, ROTATION-FROM-ROOT (old
// keypair gone entirely — the fresh domain proof adopts the new keys),
// convenience JWS rotation, signed repoint (trust root moves; slug/org
// stable), host-sweeper disable + re-proof recovery, and the admin tier act.
// Skips without AUTHKIT_TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

type mutableDocServer struct {
	mu  sync.Mutex
	doc authkit.ApplicationDocument
	srv *httptest.Server
}

func newDocServer(t *testing.T) *mutableDocServer {
	t.Helper()
	d := &mutableDocServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+authkit.ApplicationWellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.doc)
	})
	d.srv = httptest.NewServer(mux)
	t.Cleanup(d.srv.Close)
	return d
}

func (d *mutableDocServer) set(doc authkit.ApplicationDocument) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.doc = doc
}

func staticKey(t *testing.T, signer *jwtkit.RSASigner) authkit.RemoteAppKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	require.NoError(t, err)
	return authkit.RemoteAppKey{
		KID:          signer.KID(),
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
}

func postJSON(t *testing.T, h http.Handler, path string, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

func TestApplicationSelfRegistration_EndToEnd(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	cfg := newServerTestConfig()
	cfg.RBAC = []embedded.PersonaDef{{Name: "org", Parent: "root"}}
	cfg.Applications = embedded.ApplicationsConfig{SelfRegistration: true, OrgPersona: "org", AllowPrivateNetworkJWKS: true}
	client := newServerClient(t, cfg, pool)
	s, err := newServer(client)
	require.NoError(t, err)
	core := embedded.Unwrap(client)
	require.NoError(t, core.SeedPermissionGroupContainment(ctx))
	h, err := MountHandler(s, MountOptions{})
	require.NoError(t, err)

	keyA, err := jwtkit.NewRSASigner(2048, "key-a")
	require.NoError(t, err)
	keyB, err := jwtkit.NewRSASigner(2048, "key-b")
	require.NoError(t, err)

	slug := "app-" + suffix
	docSrv := newDocServer(t)
	docSrv.set(authkit.ApplicationDocument{
		Slug:        slug,
		DisplayName: "App " + suffix,
		Issuer:      docSrv.srv.URL,
		PublicKeys:  []authkit.RemoteAppKey{staticKey(t, keyA)},
	})

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE slug LIKE '%'||$1`, suffix)
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_groups WHERE instance_slug LIKE '%'||$1`, suffix)
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.name_claims WHERE owner_kind='group' AND name LIKE '%'||$1`, suffix)
	})

	// ---- register: the fetch is the domain-control proof ----
	rec, body := postJSON(t, h, "/api/v1/applications/register", map[string]any{"domain": docSrv.srv.URL})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	appObj := body["application"].(map[string]any)
	appID := appObj["id"].(string)
	require.NotEmpty(t, appID)
	require.Equal(t, slug, appObj["slug"])
	require.Equal(t, "registered", appObj["tier"], "self-registration buys existence only")
	require.Equal(t, "domain", appObj["trust_root"])
	require.Equal(t, true, appObj["enabled"])
	org := body["org"].(map[string]any)
	require.Equal(t, "org", org["persona"])
	require.Equal(t, slug, org["instance_slug"])
	require.Equal(t, true, body["created"])

	// Service-owned org: the application principal owns its own group.
	can, err := core.Can(ctx, authkit.RemoteAppSubject(appID), authkit.GroupRef{Persona: "org", Instance: slug}, embedded.PermSettingsManage("org"))
	require.NoError(t, err)
	require.True(t, can, "the application principal must own its service-owned org")

	// ---- rotation-from-root: the old keypair is GONE; re-registration
	// (a fresh domain proof) adopts the document's current keys. This is the
	// scenario the trust-root ruling exists for. ----
	docSrv.set(authkit.ApplicationDocument{
		Slug:        slug,
		DisplayName: "App " + suffix + " renamed",
		Issuer:      docSrv.srv.URL,
		PublicKeys:  []authkit.RemoteAppKey{staticKey(t, keyB)}, // key-a nowhere
	})
	rec, body = postJSON(t, h, "/api/v1/applications/register", map[string]any{"domain": docSrv.srv.URL})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, false, body["created"], "same domain re-registers idempotently")
	require.Equal(t, appID, body["application"].(map[string]any)["id"], "uuid identity is stable across re-proof")
	ra, err := core.GetRemoteApplicationBySlug(ctx, slug)
	require.NoError(t, err)
	require.Len(t, ra.PublicKeys, 1)
	require.Equal(t, "key-b", ra.PublicKeys[0].KID, "domain re-proof adopts the NEW keys with the old keypair gone")
	require.Equal(t, "App "+suffix+" renamed", ra.DisplayName)

	// ---- approval is an admin act ----
	ra2, err := core.SetApplicationTier(ctx, slug, "approved")
	require.NoError(t, err)
	require.Equal(t, "approved", ra2.Tier)

	_, err = core.SetApplicationTier(ctx, slug, "funded")
	require.ErrorIs(t, err, authkit.ErrApplicationTierInvalid)
}

func TestGroupSlugRenameTombstones(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	cfg := newServerTestConfig()
	zero := time.Duration(0)
	cfg.Naming = authkit.NamingConfig{RenameInterval: &zero}
	cfg.RBAC = []embedded.PersonaDef{{Name: "org", Parent: "root"}}
	cfg.Applications = embedded.ApplicationsConfig{SelfRegistration: true, OrgPersona: "org", AllowPrivateNetworkJWKS: true}
	client := newServerClient(t, cfg, pool)
	core := embedded.Unwrap(client)
	require.NoError(t, core.SeedPermissionGroupContainment(ctx))
	_, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_groups WHERE instance_slug LIKE '%'||$1`, suffix)
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.name_claims WHERE name LIKE '%'||$1`, suffix)
	})

	owner, err := core.CreateUser(ctx, "rename-owner-"+suffix+"@example.test", "rename_owner_"+suffix)
	require.NoError(t, err)
	oldSlug, newSlug := "human-"+suffix, "renamed-"+suffix
	gid, err := core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{
		Persona: "org", InstanceSlug: oldSlug, DisplayName: "Human Org", OwnerSubjectID: owner.ID,
	})
	require.NoError(t, err)

	_, err = core.UpdateGroupInstanceAs(ctx, owner.ID, gid, authkit.GroupInstanceUpdate{Slug: &newSlug})
	require.NoError(t, err)

	// Forwarding: the old slug resolves to the SAME group.
	got, err := core.ResolveGroupIDForSlug(ctx, authkit.GroupRef{Persona: "org", Instance: oldSlug})
	require.NoError(t, err)
	require.Equal(t, gid, got)

	// The former slug is reserved until its persisted deadline.
	_, err = core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: oldSlug})
	require.ErrorIs(t, err, authkit.ErrGroupSlugTaken)

	// The owning group may reclaim its own tombstone (rename back).
	_, err = core.UpdateGroupInstanceAs(ctx, owner.ID, gid, authkit.GroupInstanceUpdate{Slug: &oldSlug})
	require.NoError(t, err)
	got, err = core.ResolveGroupIDForSlug(ctx, authkit.GroupRef{Persona: "org", Instance: oldSlug})
	require.NoError(t, err)
	require.Equal(t, gid, got)

	// Delete-time naming rule (#264 ruling 5, final): DEFAULT delete tombstones
	// the slug to the group uuid forever — no one can re-claim it...
	require.NoError(t, core.DeletePermissionGroup(ctx, authkit.GroupRef{Persona: "org", Instance: oldSlug}, authkit.DeletePermissionGroupOptions{}))
	_, err = core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: oldSlug})
	require.ErrorIs(t, err, authkit.ErrGroupSlugTaken, "a deleted group's slug must stay reserved by default")
	// ...and its pre-existing tombstones (newSlug) stay reserved too.
	_, err = core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: newSlug})
	require.ErrorIs(t, err, authkit.ErrGroupSlugTaken)

	// Explicit ReleaseSlug frees the name (host's judgment; never-referenced
	// names only).
	relSlug := "released-" + suffix
	_, err = core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: relSlug})
	require.NoError(t, err)
	require.NoError(t, core.DeletePermissionGroup(ctx, authkit.GroupRef{Persona: "org", Instance: relSlug}, authkit.DeletePermissionGroupOptions{ReleaseSlug: true}))
	gid2, err := core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: relSlug})
	require.NoError(t, err, "an explicitly released slug must be claimable again")
	require.NotEqual(t, gid, gid2)

	// A domain-application-managed org slug refuses direct rename.
	docSrv := newDocServer(t)
	appSlug := "appmanaged-" + suffix
	keyA, err := jwtkit.NewRSASigner(2048, "key-a")
	require.NoError(t, err)
	docSrv.set(authkit.ApplicationDocument{
		Slug: appSlug, Issuer: docSrv.srv.URL,
		PublicKeys: []authkit.RemoteAppKey{staticKey(t, keyA)},
	})
	_, err = core.RegisterApplicationFromDomain(ctx, docSrv.srv.URL)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE slug = $1`, appSlug)
	})
	group, err := core.GroupInstanceForSlug(ctx, authkit.GroupRef{Persona: "org", Instance: appSlug})
	require.NoError(t, err)
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, authkit.GroupRef{Persona: "org", Instance: appSlug}, authkit.UserSubject(owner.ID), authkit.OwnerRole))
	stolen := "stolen-" + suffix
	_, err = core.UpdateGroupInstanceAs(ctx, owner.ID, group.ID, authkit.GroupInstanceUpdate{Slug: &stolen})
	require.ErrorIs(t, err, authkit.ErrGroupSlugApplicationManaged)
}
