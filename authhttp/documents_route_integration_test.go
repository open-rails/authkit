package authhttp

// ak#260 end-to-end over a real Postgres through the mounted handler: the
// authkit-owned store + publish lifecycle (documents.Service), the
// RouteDocuments mount at /.well-known/authkit/documents/{digest}, reader
// authorization from Config.Documents.Readers, digest immutability at the
// table, and the construction refusals. Skips without AUTHKIT_TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
)

const documentsTestType = "example.entitlements/v1"

// newDocumentsTestStack boots client + published document + server + mount.
func newDocumentsTestStack(t *testing.T, cfg embedded.Config, payload string) (*embedded.Client, *documents.Service, *Service, http.Handler) {
	t.Helper()
	pool := newServerTestPool(t)
	client := newServerClient(t, cfg, pool)
	docSvc, err := documents.NewService(context.Background(), documents.ServiceConfig{
		Type:      documentsTestType,
		Payload:   json.RawMessage(payload),
		Issuer:    cfg.Token.Issuer,
		Audiences: []string{"tensorhub.net"},
		Signer:    client,
		Store:     client.DocumentStore(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.signed_documents WHERE digest = $1`, docSvc.Reference().Digest)
	})
	srv, err := NewServer(client, WithDocuments(docSvc))
	require.NoError(t, err)
	h, err := MountHandler(srv, MountOptions{})
	require.NoError(t, err)
	return client, docSvc, srv, h
}

// registerDocumentReader registers a remote application (static keys) nested
// under the root group and returns a bearer token minted by ITS OWN key.
func registerDocumentReader(t *testing.T, core *embedded.Client, slug, issuer string) string {
	t.Helper()
	ctx := context.Background()
	coreSvc := embedded.Unwrap(core)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	rootGID, err := coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	_, err = coreSvc.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              slug,
		PermissionGroupID: rootGID,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys: []authkit.RemoteAppKey{{
			KID:          signer.KID(),
			PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey()),
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = coreSvc.DeleteRemoteApplication(context.Background(), issuer) })

	// A remote application addresses its token to THIS platform (ak#324: the
	// lazily-loaded issuer enforces Config.Token.ExpectedAudiences).
	token, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{
		Issuer:    issuer,
		Audiences: []string{"test-app"},
		TTL:       time.Minute,
	})
	require.NoError(t, err)
	return token
}

func getDocument(h http.Handler, method, digest, token string, header http.Header) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, documents.PublicationPathPrefix+digest, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for key, values := range header {
		for _, value := range values {
			r.Header.Set(key, value)
		}
	}
	h.ServeHTTP(w, r)
	return w
}

func TestDocumentsRoute_EndToEnd(t *testing.T) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	readerSlug := "tensorhub-" + suffix
	otherSlug := "othersvc-" + suffix

	cfg := newServerTestConfig()
	cfg.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{{Issuer: "https://" + readerSlug + ".example"}}}
	client, docSvc, srv, h := newDocumentsTestStack(t, cfg, `{"entitlements":{"free":{}}}`)
	digest := docSvc.Reference().Digest

	readerToken := registerDocumentReader(t, client, readerSlug, "https://"+readerSlug+".example")
	strangerToken := registerDocumentReader(t, client, otherSlug, "https://"+otherSlug+".example")

	// Unauthenticated and non-reader principals are denied; nothing is public.
	require.Equal(t, http.StatusUnauthorized, getDocument(h, http.MethodGet, digest, "", nil).Code)
	require.Equal(t, http.StatusUnauthorized, getDocument(h, http.MethodGet, digest, strangerToken, nil).Code,
		"an authenticated remote application NOT in Readers must be denied")
	user, err := srv.svc.CreateUser(context.Background(), "docs-user-"+suffix+"@test.example", "docsuser"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = client.Postgres().Exec(context.Background(), `DELETE FROM profiles.users WHERE id = $1::uuid`, user.ID) })
	userToken, _, err := srv.svc.MintAccessToken(context.Background(), user.ID, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, getDocument(h, http.MethodGet, digest, userToken, nil).Code,
		"a user principal is not a document reader")

	// The configured reader gets the exact compact JWS.
	rec := getDocument(h, http.MethodGet, digest, readerToken, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/jose", rec.Header().Get("Content-Type"))
	served, err := documents.FromCompact(rec.Body.String(), documents.Reference{Type: documentsTestType, Digest: digest})
	require.NoError(t, err, "served body must be the exact digest-addressed compact JWS")
	envelope, err := documents.DecodeEnvelope(served.SignedPayload)
	require.NoError(t, err)
	require.Equal(t, cfg.Token.Issuer, envelope.Issuer)
	require.JSONEq(t, `{"entitlements":{"free":{}}}`, string(envelope.Payload))

	// HEAD serves headers only; ETag revalidation returns 304.
	head := getDocument(h, http.MethodHead, digest, readerToken, nil)
	require.Equal(t, http.StatusOK, head.Code)
	require.Zero(t, head.Body.Len())
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag)
	notModified := getDocument(h, http.MethodGet, digest, readerToken, http.Header{"If-None-Match": []string{etag}})
	require.Equal(t, http.StatusNotModified, notModified.Code)

	// Unknown digest is 404 for an authorized reader.
	unknown := documents.Digest([]byte("unknown-" + suffix))
	require.Equal(t, http.StatusNotFound, getDocument(h, http.MethodGet, unknown, readerToken, nil).Code)

	// A tampered stored payload can no longer be served: the route re-checks
	// the digest/payload invariants on every read and fails closed.
	_, err = client.Postgres().Exec(context.Background(),
		`UPDATE profiles.signed_documents SET signed_payload = $1 WHERE digest = $2`,
		[]byte(`{"entitlements":{"evil":{}}}`), digest)
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, getDocument(h, http.MethodGet, digest, readerToken, nil).Code)
}

func TestDocumentsRoute_DigestImmutabilityAtTheTable(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	client := newServerClient(t, cfg, pool)

	payload := json.RawMessage(fmt.Sprintf(`{"snapshot":%d}`, time.Now().UnixNano()))
	build := func() (*documents.Service, error) {
		return documents.NewService(ctx, documents.ServiceConfig{
			Type:      documentsTestType,
			Payload:   payload,
			Issuer:    cfg.Token.Issuer,
			Audiences: []string{"tensorhub.net"},
			Signer:    client,
			Store:     client.DocumentStore(),
		})
	}
	docSvc, err := build()
	require.NoError(t, err)
	digest := docSvc.Reference().Digest
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.signed_documents WHERE digest = $1`, digest)
	})

	// Republishing the identical document is idempotent (same digest row).
	_, err = build()
	require.NoError(t, err)

	// Corrupt the stored payload under the digest: the next publish would have
	// to CHANGE immutable bytes under an existing digest, and the guarded
	// upsert refuses (documents.ErrDigestCollision), so boot fails loudly.
	_, err = pool.Exec(ctx, `UPDATE profiles.signed_documents SET signed_payload = $1 WHERE digest = $2`,
		[]byte(`{"snapshot":"drifted"}`), digest)
	require.NoError(t, err)
	_, err = build()
	require.Error(t, err)
	require.True(t, errors.Is(err, documents.ErrDigestCollision), "got: %v", err)
}

func TestNewServerRefusesDocumentsConfigMismatch(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()

	// Providers without readers: never a public route, never a 401-everything
	// route — refuse at construction.
	cfg := newServerTestConfig()
	client := newServerClient(t, cfg, pool)
	docSvc, err := documents.NewService(ctx, documents.ServiceConfig{
		Type:      documentsTestType,
		Payload:   json.RawMessage(fmt.Sprintf(`{"boot":%d}`, time.Now().UnixNano())),
		Issuer:    cfg.Token.Issuer,
		Audiences: []string{"tensorhub.net"},
		Signer:    client,
		Store:     client.DocumentStore(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.signed_documents WHERE digest = $1`, docSvc.Reference().Digest)
	})
	_, err = NewServer(client, WithDocuments(docSvc))
	require.ErrorContains(t, err, "Readers")

	// Readers without providers: dead config, refuse.
	cfgReaders := newServerTestConfig()
	cfgReaders.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{{Issuer: "https://tensorhub.example"}}}
	_, err = NewServer(newServerClient(t, cfgReaders, pool))
	require.ErrorContains(t, err, "no document providers")

	// Two providers for one document type: ambiguous stamping, refuse.
	cfgDup := newServerTestConfig()
	cfgDup.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{{Issuer: "https://tensorhub.example"}}}
	_, err = NewServer(newServerClient(t, cfgDup, pool), WithDocuments(docSvc, docSvc))
	require.ErrorContains(t, err, "two providers")
}
