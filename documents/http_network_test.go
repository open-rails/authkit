package documents_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

func TestResolverNetworkPolicy(t *testing.T) {
	ctx := context.Background()
	signer, err := jwtkit.NewRSASigner(2048, "network-policy")
	require.NoError(t, err)
	var document documents.SignedDocument
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(documents.NewPublisher(func(context.Context, string) (documents.SignedDocument, error) { return document, nil }, requireMachine))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	document, err = documents.Sign(ctx, signer, documents.Envelope{Issuer: server.URL, Audiences: []string{"site-b"}, Type: "example.entitlements/v1", Payload: json.RawMessage(`{"limit":7}`)})
	require.NoError(t, err)

	// Literal and DNS names are refused by every default transport before any
	// connection; explicit host transports can intentionally reach private TLS.
	for _, issuer := range []string{server.URL, strings.Replace(server.URL, "127.0.0.1", "localhost", 1)} {
		for _, client := range []*http.Client{nil, {}, {Transport: http.DefaultTransport}} {
			resolver := documents.NewResolver(trustedVerifier(t, issuer, signer), client, addMachine, documents.ResolverOptions{})
			_, err := resolver.Resolve(ctx, issuer, document.Reference, "site-b")
			require.ErrorContains(t, err, "private/reserved")
			require.Zero(t, connections.Load(), "private destinations must fail before dialing")
			if client != nil && client.Transport != nil {
				require.Same(t, http.DefaultTransport, client.Transport)
			}
		}
	}
	resolver := documents.NewResolver(trustedVerifier(t, server.URL, signer), server.Client(), addMachine, documents.ResolverOptions{})
	payload, err := resolver.Resolve(ctx, server.URL, document.Reference, "site-b")
	require.NoError(t, err)
	require.JSONEq(t, `{"limit":7}`, string(payload))

	// The existing development option also works with the default transport.
	local, verifier, localDocument, _ := publishedFixture(t, 0)
	defer local.Close()
	resolver = documents.NewResolver(verifier, nil, addMachine, documents.ResolverOptions{AllowHTTP: true})
	payload, err = resolver.Resolve(ctx, local.URL, localDocument.Reference, "site-b")
	require.NoError(t, err)
	require.JSONEq(t, `{"limit":7}`, string(payload))
}
