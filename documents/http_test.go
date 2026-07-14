package documents_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

const machineAuthorization = "Bearer existing-machine-credential"

type blockingRemoteSource struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingRemoteSource) ListRemoteApplications(context.Context, bool) ([]authkit.RemoteApplication, error) {
	return nil, nil
}

func (s *blockingRemoteSource) GetRemoteApplication(ctx context.Context, _ string) (*authkit.RemoteApplication, error) {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return nil, errors.New("released")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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

func TestPublisherProtocol(t *testing.T) {
	server, _, document, _ := publishedFixture(t, 0)
	defer server.Close()
	path := server.URL + documents.PublicationPathPrefix + document.Reference.Digest

	request := func(method, target, authorization string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, target, nil)
		req.Header.Set("Authorization", authorization)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := request(http.MethodGet, path, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(http.MethodPost, path, machineAuthorization)
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("method response = %d %q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	resp.Body.Close()
	missing := server.URL + documents.PublicationPathPrefix + "sha256:" + strings.Repeat("0", 64)
	resp = request(http.MethodGet, missing, machineAuthorization)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = request(http.MethodGet, path, machineAuthorization)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != document.CompactJWS || resp.Header.Get("Content-Type") != "application/jose" {
		t.Fatalf("GET = %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "private") || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("cache control = %q", resp.Header.Get("Cache-Control"))
	}
	etag := resp.Header.Get("ETag")

	req, _ := http.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", machineAuthorization)
	req.Header.Set("If-None-Match", etag)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(http.MethodHead, path, machineAuthorization)
	if resp.StatusCode != http.StatusOK || resp.ContentLength != int64(len(document.CompactJWS)) {
		t.Fatalf("HEAD = %d length %d", resp.StatusCode, resp.ContentLength)
	}
	resp.Body.Close()

	unavailable := httptest.NewServer(documents.NewPublisher(nil, requireMachine))
	defer unavailable.Close()
	req, _ = http.NewRequest(http.MethodGet, unavailable.URL+documents.PublicationPathPrefix+document.Reference.Digest, nil)
	req.Header.Set("Authorization", machineAuthorization)
	resp, err = unavailable.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestResolverAuthenticatedFetchCacheAndCoalescing(t *testing.T) {
	t.Run("cache hit", func(t *testing.T) {
		server, verifier, document, lookups := publishedFixture(t, 0)
		defer server.Close()
		resolver := documents.NewResolver(verifier, server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true})
		for range 2 {
			payload, err := resolver.Resolve(context.Background(), server.URL, document.Reference, "site-b")
			if err != nil || string(payload) != `{"limit":7}` {
				t.Fatalf("resolve = %s, %v", payload, err)
			}
		}
		if lookups.Load() != 1 {
			t.Fatalf("publisher lookups = %d, want 1", lookups.Load())
		}
	})

	t.Run("concurrent first fetch", func(t *testing.T) {
		server, verifier, document, lookups := publishedFixture(t, 40*time.Millisecond)
		defer server.Close()
		resolver := documents.NewResolver(verifier, server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true})
		start := make(chan struct{})
		errs := make(chan error, 16)
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := resolver.Resolve(context.Background(), server.URL, document.Reference, "site-b")
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if lookups.Load() != 1 {
			t.Fatalf("publisher lookups = %d, want 1", lookups.Load())
		}
	})
}

func TestResolverTimeoutCoversConcurrentIssuerFlight(t *testing.T) {
	source := &blockingRemoteSource{started: make(chan struct{}), release: make(chan struct{})}
	verifier := verify.NewVerifier()
	verifier.SetRemoteApplicationSource(source)
	reference := documents.Reference{Type: "example.entitlements/v1", Digest: documents.Digest([]byte("fixture"))}
	longResolver := documents.NewResolver(verifier, nil, addMachine, documents.ResolverOptions{Timeout: time.Second})
	shortResolver := documents.NewResolver(verifier, nil, addMachine, documents.ResolverOptions{Timeout: 20 * time.Millisecond})

	firstDone := make(chan error, 1)
	go func() {
		_, err := longResolver.Resolve(context.Background(), "https://issuer.example", reference, "site-b")
		firstDone <- err
	}()
	<-source.started

	shortDone := make(chan error, 1)
	go func() {
		_, err := shortResolver.Resolve(context.Background(), "https://issuer.example", reference, "site-b")
		shortDone <- err
	}()
	select {
	case err := <-shortDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			close(source.release)
			t.Fatalf("short Resolve() error = %v, want deadline exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(source.release)
		t.Fatal("short Resolve() inherited the stalled issuer lookup")
	}
	close(source.release)
	<-firstDone
}

func TestResolverTimeoutCoversConcurrentUnknownKIDFlight(t *testing.T) {
	oldSigner, _ := jwtkit.NewRSASigner(2048, "old-kid")
	newSigner, _ := jwtkit.NewRSASigner(2048, "new-kid")
	jwksStarted := make(chan struct{})
	jwksRelease := make(chan struct{})
	var jwksOnce sync.Once
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksOnce.Do(func() { close(jwksStarted) })
		select {
		case <-jwksRelease:
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{
				jwtkit.PublicToJWK(newSigner.PublicKey(), newSigner.KID(), newSigner.Algorithm()),
			}})
		case <-r.Context().Done():
		}
	}))
	defer jwksServer.Close()

	var document documents.SignedDocument
	publisher := httptest.NewServer(documents.NewPublisher(func(_ context.Context, digest string) (documents.SignedDocument, error) {
		if digest != document.Reference.Digest {
			return documents.SignedDocument{}, documents.ErrNotFound
		}
		return document, nil
	}, requireMachine))
	defer publisher.Close()
	var err error
	document, err = documents.Sign(context.Background(), newSigner, documents.Envelope{
		Issuer: publisher.URL, Audiences: []string{"site-b"}, Type: "example.entitlements/v1", Payload: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifier := verify.NewVerifier(verify.WithHTTPClient(jwksServer.Client()))
	if err := verifier.AddIssuer(publisher.URL, nil, verify.IssuerOptions{
		JWKSURI: jwksServer.URL,
		RawKeys: map[string]crypto.PublicKey{oldSigner.KID(): oldSigner.PublicKey()},
	}); err != nil {
		t.Fatal(err)
	}
	longResolver := documents.NewResolver(verifier, publisher.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true, Timeout: time.Second})
	shortResolver := documents.NewResolver(verifier, publisher.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true, Timeout: 20 * time.Millisecond})

	firstDone := make(chan error, 1)
	go func() {
		_, err := longResolver.Resolve(context.Background(), publisher.URL, document.Reference, "site-b")
		firstDone <- err
	}()
	<-jwksStarted

	shortDone := make(chan error, 1)
	go func() {
		_, err := shortResolver.Resolve(context.Background(), publisher.URL, document.Reference, "site-b")
		shortDone <- err
	}()
	select {
	case err := <-shortDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			close(jwksRelease)
			t.Fatalf("short Resolve() error = %v, want deadline exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(jwksRelease)
		t.Fatal("short Resolve() inherited the stalled JWKS refresh")
	}
	close(jwksRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("long Resolve() after JWKS release: %v", err)
	}
}

func TestResolverRejectsUnsafeOrInvalidFetches(t *testing.T) {
	t.Run("authentication required", func(t *testing.T) {
		server, verifier, document, lookups := publishedFixture(t, 0)
		defer server.Close()
		resolver := documents.NewResolver(verifier, server.Client(), nil, documents.ResolverOptions{AllowHTTP: true})
		if _, err := resolver.Resolve(context.Background(), server.URL, document.Reference, "site-b"); !errors.Is(err, documents.ErrUnauthorized) {
			t.Fatalf("got %v", err)
		}
		if lookups.Load() != 0 {
			t.Fatalf("unauthenticated request reached publisher")
		}
	})

	t.Run("http disabled by default", func(t *testing.T) {
		server, verifier, document, lookups := publishedFixture(t, 0)
		defer server.Close()
		resolver := documents.NewResolver(verifier, server.Client(), addMachine, documents.ResolverOptions{})
		if _, err := resolver.Resolve(context.Background(), server.URL, document.Reference, "site-b"); !errors.Is(err, documents.ErrUntrustedIssuer) {
			t.Fatalf("got %v", err)
		}
		if lookups.Load() != 0 {
			t.Fatal("HTTP rejection happened after network access")
		}
	})

	t.Run("unknown digest", func(t *testing.T) {
		server, verifier, _, _ := publishedFixture(t, 0)
		defer server.Close()
		reference := documents.Reference{Type: "example.entitlements/v1", Digest: "sha256:" + strings.Repeat("0", 64)}
		resolver := documents.NewResolver(verifier, server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true})
		if _, err := resolver.Resolve(context.Background(), server.URL, reference, "site-b"); !errors.Is(err, documents.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("off-origin redirect", func(t *testing.T) {
		var destinationHits atomic.Int32
		destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits.Add(1) }))
		defer destination.Close()
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, destination.URL, http.StatusFound)
		}))
		defer source.Close()
		signer, _ := jwtkit.NewRSASigner(2048, "kid")
		verifier := trustedVerifier(t, source.URL, signer)
		reference := documents.Reference{Type: "example.entitlements/v1", Digest: "sha256:" + strings.Repeat("0", 64)}
		resolver := documents.NewResolver(verifier, source.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true})
		if _, err := resolver.Resolve(context.Background(), source.URL, reference, "site-b"); !errors.Is(err, documents.ErrRedirect) {
			t.Fatalf("got %v", err)
		}
		if destinationHits.Load() != 0 {
			t.Fatal("cross-origin redirect reached destination")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/jose")
			_, _ = io.WriteString(w, strings.Repeat("x", 128))
		}))
		defer server.Close()
		signer, _ := jwtkit.NewRSASigner(2048, "kid")
		resolver := documents.NewResolver(trustedVerifier(t, server.URL, signer), server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true, MaxResponseBytes: 32})
		reference := documents.Reference{Type: "example.entitlements/v1", Digest: "sha256:" + strings.Repeat("0", 64)}
		if _, err := resolver.Resolve(context.Background(), server.URL, reference, "site-b"); !errors.Is(err, documents.ErrPayloadTooLarge) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(75 * time.Millisecond)
			w.Header().Set("Content-Type", "application/jose")
		}))
		defer server.Close()
		signer, _ := jwtkit.NewRSASigner(2048, "kid")
		resolver := documents.NewResolver(trustedVerifier(t, server.URL, signer), server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true, Timeout: 5 * time.Millisecond})
		reference := documents.Reference{Type: "example.entitlements/v1", Digest: "sha256:" + strings.Repeat("0", 64)}
		if _, err := resolver.Resolve(context.Background(), server.URL, reference, "site-b"); !errors.Is(err, documents.ErrFetch) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("tampered response", func(t *testing.T) {
		signer, _ := jwtkit.NewRSASigner(2048, "kid")
		var document documents.SignedDocument
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/jose")
			_, _ = io.WriteString(w, document.CompactJWS)
		}))
		defer server.Close()
		document, _ = documents.Sign(context.Background(), signer, documents.Envelope{
			Issuer: server.URL, Audiences: []string{"site-b"}, Type: "example.entitlements/v1", Payload: json.RawMessage(`{}`),
		})
		parts := strings.Split(document.CompactJWS, ".")
		if parts[2][0] == 'A' {
			parts[2] = "B" + parts[2][1:]
		} else {
			parts[2] = "A" + parts[2][1:]
		}
		document.CompactJWS = strings.Join(parts, ".")
		resolver := documents.NewResolver(trustedVerifier(t, server.URL, signer), server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true})
		if _, err := resolver.Resolve(context.Background(), server.URL, document.Reference, "site-b"); !errors.Is(err, documents.ErrInvalidSignature) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestResolverCacheIsBounded(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid")
	documentsByDigest := map[string]documents.SignedDocument{}
	var lookups atomic.Int32
	server := httptest.NewServer(documents.NewPublisher(func(_ context.Context, digest string) (documents.SignedDocument, error) {
		lookups.Add(1)
		document, ok := documentsByDigest[digest]
		if !ok {
			return documents.SignedDocument{}, documents.ErrNotFound
		}
		return document, nil
	}, requireMachine))
	defer server.Close()
	for i := 1; i <= 2; i++ {
		document, err := documents.Sign(context.Background(), signer, documents.Envelope{
			Issuer: server.URL, Audiences: []string{"site-b"}, Type: fmt.Sprintf("example.type%d/v1", i), Payload: json.RawMessage(fmt.Sprintf(`{"n":%d}`, i)),
		})
		if err != nil {
			t.Fatal(err)
		}
		documentsByDigest[document.Reference.Digest] = document
	}
	var refs []documents.Reference
	for _, document := range documentsByDigest {
		refs = append(refs, document.Reference)
	}
	resolver := documents.NewResolver(trustedVerifier(t, server.URL, signer), server.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true, MaxCacheEntries: 1})
	for _, reference := range []documents.Reference{refs[0], refs[1], refs[0]} {
		if _, err := resolver.Resolve(context.Background(), server.URL, reference, "site-b"); err != nil {
			t.Fatal(err)
		}
	}
	if lookups.Load() != 3 {
		t.Fatalf("lookups = %d, want eviction to force third fetch", lookups.Load())
	}
}

func ExampleResolver_twoSites() {
	signer, _ := jwtkit.NewRSASigner(2048, "site-a-key")
	var document documents.SignedDocument
	siteA := httptest.NewServer(documents.NewPublisher(func(context.Context, string) (documents.SignedDocument, error) {
		return document, nil
	}, requireMachine))
	defer siteA.Close()
	document, _ = documents.Sign(context.Background(), signer, documents.Envelope{
		Issuer: siteA.URL, Audiences: []string{"site-b"}, Type: "example.entitlements/v1", Payload: json.RawMessage(`{"plan":"starter"}`),
	})

	v := verify.NewVerifier()
	_ = v.AddIssuer(siteA.URL, nil, verify.IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}})
	resolver := documents.NewResolver(v, siteA.Client(), addMachine, documents.ResolverOptions{AllowHTTP: true})
	siteB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := resolver.Resolve(r.Context(), siteA.URL, document.Reference, "site-b")
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(payload) // site B owns schema/processing from here.
	}))
	defer siteB.Close()

	response, _ := siteB.Client().Get(siteB.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	fmt.Println(string(body))
	// Output: {"plan":"starter"}
}
