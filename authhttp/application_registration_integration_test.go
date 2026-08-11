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
	"github.com/open-rails/authkit/jwtkit"
)

const appReqJOSEType = "authkit-application-request+jws" // pinned wire contract

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

func signAppJWS(t *testing.T, signer *jwtkit.RSASigner, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	compact, err := jwtkit.SignPayloadWithType(context.Background(), signer, raw, appReqJOSEType)
	require.NoError(t, err)
	return compact
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
	pool := newServerTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	cfg := newServerTestConfig() // Environment empty => dev-like (loopback allowed)
	cfg.RBAC = []embedded.PersonaDef{{Name: "org", Parent: "root"}}
	cfg.Applications = embedded.ApplicationsConfig{SelfRegistration: true, OrgPersona: "org"}
	client := newServerClient(t, cfg, pool)
	s, err := NewServer(client)
	require.NoError(t, err)
	core := embedded.Unwrap(client)
	require.NoError(t, core.SeedPermissionGroupContainment(ctx))
	h, err := MountHandler(s, MountOptions{})
	require.NoError(t, err)

	keyA, err := jwtkit.NewRSASigner(2048, "key-a")
	require.NoError(t, err)
	keyB, err := jwtkit.NewRSASigner(2048, "key-b")
	require.NoError(t, err)
	keyC, err := jwtkit.NewRSASigner(2048, "key-c")
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_group_slug_tombstones WHERE slug LIKE '%'||$1`, suffix)
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
	can, err := core.Can(ctx, appID, embedded.SubjectKindRemoteApp, "org", slug, embedded.PermSettingsManage("org"))
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

	// ---- convenience rotation: old key signs the new trust source ----
	rotate := signAppJWS(t, keyB, map[string]any{
		"op":   "rotate",
		"slug": slug,
		"aud":  cfg.Token.Issuer,
		"iat":  time.Now().Unix(),
		"public_keys": []map[string]string{
			{"kid": "key-c", "public_key_pem": staticKey(t, keyC).PublicKeyPEM},
		},
	})
	rec, _ = postJSON(t, h, "/api/v1/applications/"+slug+"/rotate", map[string]any{"jws": rotate})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ra, err = core.GetRemoteApplicationBySlug(ctx, slug)
	require.NoError(t, err)
	require.Equal(t, "key-c", ra.PublicKeys[0].KID)

	// Stale iat is refused (anti-replay window).
	stale := signAppJWS(t, keyC, map[string]any{
		"op": "rotate", "slug": slug, "aud": cfg.Token.Issuer,
		"iat":         time.Now().Add(-time.Hour).Unix(),
		"public_keys": []map[string]string{{"kid": "key-c", "public_key_pem": staticKey(t, keyC).PublicKeyPEM}},
	})
	rec, _ = postJSON(t, h, "/api/v1/applications/"+slug+"/rotate", map[string]any{"jws": stale})
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "application_signature_stale")

	// ---- repoint: the TRUST ROOT moves to a new domain; uuid, slug, and the
	// org are all stable (slugs and domains are separate) ----
	docSrv2 := newDocServer(t)
	docSrv2.set(authkit.ApplicationDocument{
		DisplayName: "App " + suffix + " moved",
		Issuer:      docSrv2.srv.URL,
		PublicKeys:  []authkit.RemoteAppKey{staticKey(t, keyC)},
	})
	repoint := signAppJWS(t, keyC, map[string]any{
		"op": "repoint", "slug": slug, "aud": cfg.Token.Issuer,
		"iat": time.Now().Unix(), "domain": docSrv2.srv.URL,
	})
	rec, body = postJSON(t, h, "/api/v1/applications/"+slug+"/repoint", map[string]any{"jws": repoint})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, slug, body["application"].(map[string]any)["slug"], "slug is a claimed handle, stable across repoint")
	require.Equal(t, appID, body["application"].(map[string]any)["id"], "uuid stable across repoint")
	require.Equal(t, docSrv2.srv.URL, body["application"].(map[string]any)["domain"], "trust root moved")
	require.Equal(t, slug, body["org"].(map[string]any)["instance_slug"], "org unchanged")

	// The OLD domain is free again: a new registrant there gets a NEW identity.
	docSrv.set(authkit.ApplicationDocument{
		Slug:       "newowner-" + suffix,
		Issuer:     docSrv.srv.URL + "/other", // distinct issuer
		PublicKeys: []authkit.RemoteAppKey{staticKey(t, keyA)},
	})
	rec, body = postJSON(t, h, "/api/v1/applications/register", map[string]any{"domain": docSrv.srv.URL})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.NotEqual(t, appID, body["application"].(map[string]any)["id"], "a re-registered old domain is a fresh identity")

	// ---- host sweeper disables a stale registration; re-proof re-enables ----
	// (#264 ruling 5, simplified: re-verification cadence is HOST policy — the
	// host reads RootVerifiedAt and calls SetApplicationEnabled.)
	ra, err = core.SetApplicationEnabled(ctx, slug, false)
	require.NoError(t, err)
	require.False(t, ra.Enabled)

	// A disabled app's keys are no longer trusted for signed requests.
	rec, _ = postJSON(t, h, "/api/v1/applications/"+slug+"/rotate", map[string]any{"jws": signAppJWS(t, keyC, map[string]any{
		"op": "rotate", "slug": slug, "aud": cfg.Token.Issuer, "iat": time.Now().Unix(),
		"public_keys": []map[string]string{{"kid": "key-c", "public_key_pem": staticKey(t, keyC).PublicKeyPEM}},
	})})
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Recovery is the trust root: re-register (fresh domain proof).
	rec, _ = postJSON(t, h, "/api/v1/applications/register", map[string]any{"domain": docSrv2.srv.URL})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ra, err = core.GetRemoteApplicationBySlug(ctx, slug)
	require.NoError(t, err)
	require.True(t, ra.Enabled, "re-proving the root re-enables the application")

	// ---- approval is an admin act ----
	ra2, err := core.SetApplicationTier(ctx, slug, "approved")
	require.NoError(t, err)
	require.Equal(t, "approved", ra2.Tier)

	_, err = core.SetApplicationTier(ctx, slug, "funded")
	require.ErrorIs(t, err, authkit.ErrApplicationTierInvalid)
}

func TestGroupSlugRenameTombstones(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	cfg := newServerTestConfig()
	cfg.RBAC = []embedded.PersonaDef{{Name: "org", Parent: "root"}}
	cfg.Applications = embedded.ApplicationsConfig{SelfRegistration: true, OrgPersona: "org"}
	client := newServerClient(t, cfg, pool)
	core := embedded.Unwrap(client)
	require.NoError(t, core.SeedPermissionGroupContainment(ctx))
	_, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_groups WHERE instance_slug LIKE '%'||$1`, suffix)
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_group_slug_tombstones WHERE slug LIKE '%'||$1`, suffix)
	})

	oldSlug, newSlug := "human-"+suffix, "renamed-"+suffix
	gid, err := core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{
		Persona: "org", InstanceSlug: oldSlug, DisplayName: "Human Org",
	})
	require.NoError(t, err)

	require.NoError(t, core.RenamePermissionGroupSlug(ctx, "org", oldSlug, newSlug))

	// Forwarding: the old slug resolves to the SAME group.
	got, err := core.ResolveGroupIDForSlug(ctx, "org", oldSlug)
	require.NoError(t, err)
	require.Equal(t, gid, got)

	// The tombstoned slug is never claimable by a NEW group.
	_, err = core.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: oldSlug})
	require.ErrorIs(t, err, authkit.ErrGroupSlugTaken)

	// The owning group may reclaim its own tombstone (rename back).
	require.NoError(t, core.RenamePermissionGroupSlug(ctx, "org", newSlug, oldSlug))
	got, err = core.ResolveGroupIDForSlug(ctx, "org", oldSlug)
	require.NoError(t, err)
	require.Equal(t, gid, got)

	// Delete-time naming rule (#264 ruling 5, final): DEFAULT delete tombstones
	// the slug to the group uuid forever — no one can re-claim it...
	require.NoError(t, core.DeletePermissionGroup(ctx, "org", oldSlug, authkit.DeletePermissionGroupOptions{}))
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
	require.NoError(t, core.DeletePermissionGroup(ctx, "org", relSlug, authkit.DeletePermissionGroupOptions{ReleaseSlug: true}))
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
	err = core.RenamePermissionGroupSlug(ctx, "org", appSlug, "stolen-"+suffix)
	require.ErrorIs(t, err, authkit.ErrGroupSlugApplicationManaged)
}
