package authhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

// Audit regression: this is exactly a text/plain HTML form's name=value body.
// name = {"identifier":"audit-csrf@example.test","password":"
// value = Attack-password-12345"}
// The separator '=' becomes the first character of the attacker's password.
func TestV1AuditCookieLoginRejectsCrossOriginForm(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newServerClient(t, refreshCookieTestConfig(), pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	user, err := core.CreateUser(ctx, "audit-csrf@example.test", "audit-csrf")
	require.NoError(t, err)
	phc, err := password.HashArgon2id("=Attack-password-12345")
	require.NoError(t, err)
	require.NoError(t, core.UpsertPasswordHash(ctx, user.ID, phc, "argon2id", nil))
	h, err := MountHandler(srv, MountOptions{RefreshCookie: true})
	require.NoError(t, err)
	body := `{"identifier":"audit-csrf@example.test","password":"=Attack-password-12345"}` + "\r\n"
	r := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/password/login", strings.NewReader(body))
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	c := refreshCookieOf(t, w)
	t.Logf("cross-origin browser form login HTTP=%d; refresh cookie set=%v", w.Code, c != nil && c.Value != "")
	require.NotEqual(t, http.StatusOK, w.Code, "cookie login must not accept cross-origin HTML form credentials")
	require.Nil(t, c, "cross-origin login must not replace the browser's session")
}

// Audit regression: registered issuer status does not authorize private egress.
// With the default client TLS still rejects the local untrusted certificate;
// the observed TCP connection itself proves the missing network guard.
func TestV1AuditDocumentResolverDeniesPrivateDial(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newScopeBindingCore(t, pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	require.False(t, core.Config().Applications.AllowPrivateNetworkJWKS)
	var connections atomic.Int32
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	internal.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connections.Add(1)
		}
	}
	internal.StartTLS()
	defer internal.Close()
	signer, err := jwtkit.NewRSASigner(2048, "audit-document-kid")
	require.NoError(t, err)
	gid := createRepoGroup(t, ctx, core, pg.Pool, "audit-documents")
	_, err = core.UpsertRemoteApplication(ctx, authkit.RemoteApplication{Slug: "audit-documents", PermissionGroupID: gid, Issuer: internal.URL, Enabled: true, PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}}})
	require.NoError(t, err)
	resolver := documents.NewResolver(srv.Verifier(), nil, func(*http.Request) error { return nil }, documents.ResolverOptions{})
	ref := documents.Reference{Type: "audit.policy/v1", Digest: documents.Digest([]byte("audit"))}
	_, err = resolver.Resolve(ctx, internal.URL, ref, "test-app")
	require.Error(t, err, "normal TLS correctly rejects the untrusted test certificate")
	t.Logf("default resolver contacted private HTTPS listener %d time(s); final error=%v", connections.Load(), err)
	require.Zero(t, connections.Load(), "default document transport must reject private egress before opening a connection")
}
