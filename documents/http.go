package documents

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const PublicationPathPrefix = "/.well-known/authkit/documents/"

// AuthorizeRequest either authenticates an incoming publisher request or adds
// existing machine credentials to an outgoing resolver request. Nil always
// denies; AuthKit does not define a document-specific credential.
type AuthorizeRequest func(*http.Request) error

// LookupDocument returns a previously signed immutable document by digest.
type LookupDocument func(context.Context, string) (SignedDocument, error)

// NewPublisher returns the framework-neutral well-known publication handler.
func NewPublisher(lookup LookupDocument, authorize AuthorizeRequest) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		digest, ok := strings.CutPrefix(r.URL.Path, PublicationPathPrefix)
		if !ok || strings.Contains(digest, "/") || ValidateDigest(digest) != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if authorize == nil || authorize(r) != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if lookup == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		document, err := lookup(r.Context(), digest)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		parsed, err := FromCompact(document.CompactJWS, document.Reference)
		if err != nil || document.Reference.Digest != digest || !bytes.Equal(parsed.SignedPayload, document.SignedPayload) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		etag := strconv.Quote(digest)
		w.Header().Set("Content-Type", "application/jose")
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
		w.Header().Set("ETag", etag)
		if etagMatches(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(document.CompactJWS)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, document.CompactJWS)
	})
}

func etagMatches(values, target string) bool {
	for _, value := range strings.Split(values, ",") {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

// DocumentVerifier is implemented by verify.Verifier. The preflight trust
// check prevents an untrusted issuer from becoming a network destination.
type DocumentVerifier interface {
	ValidateDocumentIssuer(context.Context, string) error
	VerifyDocument(context.Context, SignedDocument, VerifyOptions) (Envelope, error)
}

type ResolverOptions struct {
	// AllowHTTP is for local tests and development only. Production defaults to
	// HTTPS-only publication endpoints.
	AllowHTTP        bool
	Timeout          time.Duration
	MaxResponseBytes int64
	MaxCacheEntries  int
}

type Resolver struct {
	verifier  DocumentVerifier
	client    *http.Client
	authorize AuthorizeRequest
	opts      ResolverOptions

	mu      sync.Mutex
	cache   map[string]*list.Element
	lru     *list.List
	flights map[string]*resolveFlight
}

type cachedDocument struct {
	key      string
	envelope Envelope
}

type resolveFlight struct {
	done     chan struct{}
	envelope Envelope
	err      error
}

func NewResolver(verifier DocumentVerifier, client *http.Client, authorize AuthorizeRequest, opts ResolverOptions) *Resolver {
	if client == nil {
		client = http.DefaultClient
	}
	clientCopy := *client
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxResponseBytes <= 0 || opts.MaxResponseBytes > MaxCompactJWSBytes {
		opts.MaxResponseBytes = MaxCompactJWSBytes
	}
	if opts.MaxCacheEntries <= 0 {
		opts.MaxCacheEntries = 256
	}
	return &Resolver{
		verifier: verifier, client: &clientCopy, authorize: authorize, opts: opts,
		cache: map[string]*list.Element{}, lru: list.New(), flights: map[string]*resolveFlight{},
	}
}

// Resolve authenticates, fetches, verifies, and returns only the opaque
// application payload. Successful results are cached by issuer+type+digest.
func (r *Resolver) Resolve(ctx context.Context, issuer string, reference Reference, audience string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	issuer = strings.TrimSpace(issuer)
	audience = strings.TrimSpace(audience)
	if issuer == "" || audience == "" || len(audience) > MaxAudienceBytes {
		return nil, ErrInvalidReference
	}
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	if r.verifier == nil {
		return nil, ErrUntrustedIssuer
	}
	if err := r.verifier.ValidateDocumentIssuer(ctx, issuer); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	key := issuer + "\x00" + reference.Type + "\x00" + reference.Digest
	if envelope, ok := r.cached(key); ok {
		return payloadForAudience(envelope, audience)
	}

	// Coalesce identical first fetches. Audience is part of the flight key so a
	// mismatch for one audience cannot poison a simultaneous valid request; the
	// durable cache remains issuer+type+digest as required.
	flightKey := key + "\x00" + audience
	r.mu.Lock()
	if flight := r.flights[flightKey]; flight != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-flight.done:
			if flight.err != nil {
				return nil, flight.err
			}
			return payloadForAudience(flight.envelope, audience)
		}
	}
	flight := &resolveFlight{done: make(chan struct{})}
	r.flights[flightKey] = flight
	r.mu.Unlock()

	envelope, err := r.fetch(ctx, issuer, reference, audience)
	if err == nil {
		r.store(key, envelope)
	}
	r.mu.Lock()
	flight.envelope, flight.err = envelope, err
	delete(r.flights, flightKey)
	close(flight.done)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return payloadForAudience(envelope, audience)
}

func payloadForAudience(envelope Envelope, audience string) (json.RawMessage, error) {
	if !envelope.HasAudience(audience) {
		return nil, ErrAudienceMismatch
	}
	return append(json.RawMessage(nil), envelope.Payload...), nil
}

func (r *Resolver) cached(key string) (Envelope, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	element := r.cache[key]
	if element == nil {
		return Envelope{}, false
	}
	r.lru.MoveToFront(element)
	return element.Value.(cachedDocument).envelope, true
}

func (r *Resolver) store(key string, envelope Envelope) {
	envelope.Payload = append(json.RawMessage(nil), envelope.Payload...)
	r.mu.Lock()
	defer r.mu.Unlock()
	if element := r.cache[key]; element != nil {
		element.Value = cachedDocument{key: key, envelope: envelope}
		r.lru.MoveToFront(element)
		return
	}
	element := r.lru.PushFront(cachedDocument{key: key, envelope: envelope})
	r.cache[key] = element
	for r.lru.Len() > r.opts.MaxCacheEntries {
		oldest := r.lru.Back()
		delete(r.cache, oldest.Value.(cachedDocument).key)
		r.lru.Remove(oldest)
	}
}

func (r *Resolver) fetch(ctx context.Context, issuer string, reference Reference, audience string) (Envelope, error) {
	if r.authorize == nil {
		return Envelope{}, ErrUnauthorized
	}
	endpoint, origin, err := publicationURL(issuer, reference.Digest, r.opts.AllowHTTP)
	if err != nil {
		return Envelope{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/jose")
	if err := r.authorize(req); err != nil {
		return Envelope{}, ErrUnauthorized
	}

	client := *r.client
	originalRedirect := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 4 || !sameOrigin(origin, next.URL) {
			return ErrRedirect
		}
		if originalRedirect != nil {
			return originalRedirect(next, via)
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return Envelope{}, ErrRedirect
		}
		return Envelope{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Envelope{}, ErrUnauthorized
	case http.StatusNotFound:
		return Envelope{}, ErrNotFound
	default:
		return Envelope{}, fmt.Errorf("%w: http %d", ErrFetch, resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/jose" {
		return Envelope{}, fmt.Errorf("%w: wrong content type", ErrFetch)
	}
	if resp.ContentLength > r.opts.MaxResponseBytes {
		return Envelope{}, ErrPayloadTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, r.opts.MaxResponseBytes+1))
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	if int64(len(body)) > r.opts.MaxResponseBytes {
		return Envelope{}, ErrPayloadTooLarge
	}
	document, err := FromCompact(string(body), reference)
	if err != nil {
		return Envelope{}, err
	}
	return r.verifier.VerifyDocument(ctx, document, VerifyOptions{
		Issuer: issuer, Audience: audience, Type: reference.Type, Reference: reference,
	})
}

func publicationURL(issuer, digest string, allowHTTP bool) (string, *url.URL, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, ErrUntrustedIssuer
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return "", nil, ErrUntrustedIssuer
	}
	origin := &url.URL{Scheme: strings.ToLower(u.Scheme), Host: strings.ToLower(u.Host)}
	u.Path = PublicationPathPrefix + digest
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), origin, nil
}

func sameOrigin(want, got *url.URL) bool {
	if want == nil || got == nil || !strings.EqualFold(want.Scheme, got.Scheme) || !strings.EqualFold(want.Hostname(), got.Hostname()) {
		return false
	}
	return canonicalPort(want) == canonicalPort(got)
}

func canonicalPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
