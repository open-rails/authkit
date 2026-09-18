package documents_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"

	"net/http"
	"net/http/httptest"

	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

const machineAuthorization = "Bearer existing-machine-credential"

func requireMachine(request *http.Request) error {
	if request.Header.Get("Authorization") != machineAuthorization {
		return errors.New("unauthorized")
	}
	return nil
}

func addMachine(request *http.Request) error {
	request.Header.Set("Authorization", machineAuthorization)
	return nil
}

func trustedVerifier(t *testing.T, issuer string, signer *jwtkit.RSASigner) *verify.Verifier {
	t.Helper()
	v := verify.NewVerifier()
	if err := v.AddIssuer(issuer, nil, verify.IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}); err != nil {
		t.Fatal(err)
	}
	return v
}

func publishedFixture(t *testing.T, delay time.Duration) (*httptest.Server, *verify.Verifier, documents.SignedDocument, *atomic.Int32) {
	t.Helper()
	signer, _ := jwtkit.NewRSASigner(2048, "publisher-kid")
	var (
		document documents.SignedDocument
		lookups  atomic.Int32
	)
	server := httptest.NewServer(documents.NewPublisher(func(_ context.Context, digest string) (documents.SignedDocument, error) {
		lookups.Add(1)
		if delay > 0 {
			time.Sleep(delay)
		}
		if digest != document.Reference.Digest {
			return documents.SignedDocument{}, documents.ErrNotFound
		}
		return document, nil
	}, requireMachine))
	var err error
	document, err = documents.Sign(context.Background(), signer, documents.Envelope{
		Issuer: server.URL, Audiences: []string{"site-b"}, Type: "example.entitlements/v1", Payload: json.RawMessage(`{"limit":7}`),
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return server, trustedVerifier(t, server.URL, signer), document, &lookups
}
