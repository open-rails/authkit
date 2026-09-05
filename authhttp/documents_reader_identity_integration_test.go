package authhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

// registerReaderApp registers a static-key remote application under gid and
// returns its id plus a bearer token minted by its own key.
func registerReaderApp(t *testing.T, core *embedded.Client, gid, slug, issuer string) (id, token string) {
	t.Helper()
	ctx := context.Background()
	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	ra, err := core.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug: slug, PermissionGroupID: gid, Issuer: issuer, Enabled: true,
		PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	})
	require.NoError(t, err)
	token, err = embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{Issuer: issuer, Audiences: []string{"test-app"}, TTL: time.Minute})
	require.NoError(t, err)
	return ra.ID, token
}

// #296: document readers are pinned by an identity nobody else can claim —
// application id, proven domain, or a ROOT-registered issuer — never by slug,
// and only at the approved tier unless the host opts registered readers in.
func TestDocumentsRoute_ReadersKeyedByIdentityNotSlug(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	issuer := func(name string) string { return "https://" + name + "-" + suffix + ".example" }

	base := newServerTestConfig()
	base.RBAC = []embedded.PersonaDef{{Name: "org", Parent: "root", Capabilities: embedded.PersonaCapabilities{RemoteApplications: true}}}

	// Registration happens before the reader config exists (the host's own
	// boot order: bootstrap manifest, then readers by identity).
	pre := newServerClient(t, base, pool)
	coreSvc := pre
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	rootGID, err := coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	tenantGID, err := coreSvc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "tenant-" + suffix})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE issuer LIKE '%'||$1||'.example'`, suffix)
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_groups WHERE id = $1::uuid`, tenantGID)
	})
	setDomainRooted := func(iss, domain, tier string) {
		t.Helper()
		_, err := pool.Exec(ctx, `UPDATE profiles.remote_applications SET trust_root = 'domain', domain = $2, tier = $3 WHERE issuer = $1`, iss, domain, tier)
		require.NoError(t, err)
	}

	_, rootToken := registerReaderApp(t, pre, rootGID, "tensorhub-"+suffix, issuer("tensorhub"))
	_, tenantIssuerToken := registerReaderApp(t, pre, tenantGID, "tenantiss-"+suffix, issuer("tenantiss"))
	idReader, idToken := registerReaderApp(t, pre, tenantGID, "byid-"+suffix, issuer("byid"))
	_, domainToken := registerReaderApp(t, pre, rootGID, "reader-"+suffix, issuer("reader"))
	setDomainRooted(issuer("reader"), "reader-"+suffix+".example", authkit.ApplicationTierRegistered)
	// A self-registered squatter: approved, domain-rooted, but on a foreign domain.
	_, squatToken := registerReaderApp(t, pre, tenantGID, "squat-"+suffix, issuer("squat"))
	setDomainRooted(issuer("squat"), "squat-"+suffix+".example", authkit.ApplicationTierApproved)

	cfg := base
	cfg.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{
		{Issuer: issuer("tensorhub")},
		{Issuer: issuer("tenantiss")},
		{Domain: "Reader-" + suffix + ".example"},
		{ID: idReader},
	}}
	// One advisory-locked pool per test: build the stacks on the pool we hold.
	stack := func(cfg embedded.Config, payload string) (string, http.Handler) {
		t.Helper()
		client := newServerClient(t, cfg, pool)
		docSvc, err := documents.NewService(ctx, documents.ServiceConfig{
			Type: documentsTestType, Payload: json.RawMessage(payload), Issuer: cfg.Token.Issuer,
			Audiences: []string{"tensorhub.net"}, Signer: client, Store: client.DocumentStore(),
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.signed_documents WHERE digest = $1`, docSvc.Reference().Digest)
		})
		srv, err := newServer(client, WithDocuments(docSvc))
		require.NoError(t, err)
		h, err := MountHandler(srv, MountOptions{})
		require.NoError(t, err)
		return docSvc.Reference().Digest, h
	}
	digest, h := stack(cfg, `{"readers":"`+suffix+`"}`)
	status := func(token string) int { return getDocument(h, http.MethodGet, digest, token, nil).Code }

	require.Equal(t, http.StatusOK, status(rootToken), "root-registered issuer reads")
	require.Equal(t, http.StatusOK, status(idToken), "reader pinned by id reads regardless of group")
	require.Equal(t, http.StatusUnauthorized, status(tenantIssuerToken), "an issuer entry never matches a tenant-registered application")
	require.Equal(t, http.StatusUnauthorized, status(squatToken), "the reader's slug on a foreign domain is not a reader")
	require.Equal(t, http.StatusUnauthorized, status(domainToken), "registered tier is refused by default")
	setDomainRooted(issuer("reader"), "reader-"+suffix+".example", authkit.ApplicationTierApproved)
	require.Equal(t, http.StatusOK, status(domainToken), "approved domain-rooted reader reads")

	// Host opts registered-tier readers in.
	setDomainRooted(issuer("reader"), "reader-"+suffix+".example", authkit.ApplicationTierRegistered)
	cfg.Documents.AllowRegisteredTier = true
	digest2, h2 := stack(cfg, `{"readers-registered":"`+suffix+`"}`)
	require.Equal(t, http.StatusOK, getDocument(h2, http.MethodGet, digest2, domainToken, nil).Code)
	require.Equal(t, http.StatusUnauthorized, getDocument(h2, http.MethodGet, digest2, squatToken, nil).Code)
}

func TestNewServerRefusesAmbiguousDocumentReader(t *testing.T) {
	cfg := newServerTestConfig()
	cfg.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{{ID: "x", Issuer: "https://x.example"}}}
	_, err := embedded.New(cfg, embedded.Deps{Postgres: testdb.Pool(t)})
	require.ErrorContains(t, err, "exactly one of ID, Domain, Issuer")
}
