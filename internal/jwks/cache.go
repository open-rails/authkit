// Package jwks is the issuer key cache behind every AuthKit verifier: an
// issuer's JWKS read through helpers/cache under cachepolicy.IssuerKeys,
// refetched on key rotation, with per-issuer health. Public verify uses it
// for the issuers a host adds; the engine for remote applications.
package jwks

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/open-rails/authkit/internal/cachepolicy"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/keypolicy"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/helpers/cache"
)

// Issuer is one issuer's JWKS endpoint.
type Issuer struct {
	Issuer string
	URL    string
}

// Cache holds fetched keys per issuer. Every count in it is bounded by the
// issuers its owner registered, never by request traffic.
type Cache struct {
	client *http.Client
	opts   cache.Options
	keys   *cache.Cache[Issuer, map[string]crypto.PublicKey]

	mu     sync.Mutex
	health map[string]*health
}

// health is a registered issuer's fetch record.
type health struct {
	is                   Issuer
	keys                 int
	fetchedAt, checkedAt time.Time
	failures             int
	lastErr              error

	refetchAt time.Time
	refetch   *flight
}

// flight is a running refetch; its keys are set when done closes.
type flight struct {
	done chan struct{}
	keys map[string]crypto.PublicKey
}

// New returns a cache fetching with client (nil: a timeout-bounded client
// that may reach private addresses) under policy o.
func New(client *http.Client, o cache.Options) *Cache {
	if client == nil {
		client = netguard.Client(netguard.DefaultTimeout, true)
	}
	c := &Cache{client: client, opts: o, health: map[string]*health{}}
	c.keys = cachepolicy.New(o, c.load)
	return c
}

// Register trusts is.URL for is.Issuer's keys, forgetting keys fetched from
// an earlier endpoint.
func (c *Cache) Register(is Issuer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.health[is.Issuer]; h != nil {
		if h.is == is {
			return
		}
		c.keys.Invalidate(h.is)
	}
	c.health[is.Issuer] = &health{is: is}
}

// Close stops the cache's background work; it keeps serving.
func (c *Cache) Close() { c.keys.Close() }

// Drop forgets iss's keys.
func (c *Cache) Drop(iss string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.health[iss]; h != nil {
		c.keys.Invalidate(h.is)
		delete(c.health, iss)
	}
}

// Key returns the key kid names from is's JWKS. A request waits only when the
// issuer has no usable keys, and then for at most one bounded load; an
// unknown kid on a healthy issuer forces one throttled refetch (rotation).
func (c *Cache) Key(ctx context.Context, is Issuer, kid string) (crypto.PublicKey, error) {
	m, err := c.keys.Get(ctx, []Issuer{is})
	set, ok := m[is]
	if !ok {
		return nil, unavailable(cmp.Or(err, c.lastErr(is), errNoKeys))
	}
	if len(set) == 0 {
		// The issuer published no usable keys: fail closed until a refetch finds some.
		if set, _ = c.refetch(ctx, is); len(set) == 0 {
			return nil, unavailable(cmp.Or(c.lastErr(is), errNoKeys))
		}
	}
	key, err := Select(set, kid)
	if err == nil || kid == "" {
		return key, err
	}
	// While the issuer is failing, its reloads own refetching.
	if lastErr := c.lastErr(is); lastErr != nil {
		return nil, unavailable(lastErr)
	}
	if set, ok := c.refetch(ctx, is); ok {
		key, err = Select(set, kid)
	}
	return key, err
}

// Refresh forces one throttled refetch of a healthy issuer's keys after a
// signature failed under them: a rotated key that kept its kid. It reports
// whether a refetch ran, so the caller retries once.
func (c *Cache) Refresh(ctx context.Context, is Issuer) bool {
	if c.lastErr(is) != nil {
		return false
	}
	_, ok := c.refetch(ctx, is)
	return ok
}

var errNoKeys = errors.New("issuer has no usable keys")

func unavailable(cause error) error {
	return errmodel.E(errmodel.CodeIssuerKeysUnavailable, errmodel.WithCause(cause))
}

func (c *Cache) lastErr(is Issuer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.health[is.Issuer]; h != nil && h.is == is {
		return h.lastErr
	}
	return nil
}

// refetch reloads is's keys at most once per IssuerKeysRefetchMin, so a storm
// of bad kids or signatures cannot hammer the endpoint; callers arriving
// meanwhile share it. A failed reload keeps the cached keys.
func (c *Cache) refetch(ctx context.Context, is Issuer) (map[string]crypto.PublicKey, bool) {
	c.mu.Lock()
	h := c.health[is.Issuer]
	switch {
	case h == nil || h.is != is:
		c.mu.Unlock()
		return nil, false
	case h.refetch != nil:
		f := h.refetch
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.keys, true
		case <-ctx.Done():
			return nil, false
		}
	case !h.refetchAt.IsZero() && c.now().Sub(h.refetchAt) < cachepolicy.IssuerKeysRefetchMin:
		c.mu.Unlock()
		return nil, false
	}
	f := &flight{done: make(chan struct{})}
	h.refetch = f
	c.mu.Unlock()

	m, _ := c.keys.Refresh(context.WithoutCancel(ctx), []Issuer{is})
	f.keys = m[is]

	c.mu.Lock()
	h.refetchAt, h.refetch = c.now(), nil
	close(f.done)
	c.mu.Unlock()
	return f.keys, true
}

// load fetches each issuer's keys. A transient failure keeps the cached keys
// (bounded by MaxStale); an authoritative JWKS without usable keys replaces
// them with none (fail closed).
func (c *Cache) load(ctx context.Context, issuers []Issuer) (map[Issuer]map[string]crypto.PublicKey, error) {
	out := make(map[Issuer]map[string]crypto.PublicKey, len(issuers))
	var errs []error
	for _, is := range issuers {
		set, authoritative, err := c.get(ctx, is.URL)
		c.record(is, len(set), authoritative, err)
		switch {
		case err == nil:
			out[is] = set
		case authoritative:
			out[is] = map[string]crypto.PublicKey{}
		default:
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

func (c *Cache) record(is Issuer, n int, authoritative bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.health[is.Issuer]
	if h == nil || h.is != is {
		return
	}
	h.checkedAt, h.lastErr = c.now(), err
	switch {
	case err == nil:
		h.keys, h.fetchedAt, h.failures = n, h.checkedAt, 0
	case authoritative:
		h.keys = 0
		h.failures++
	default:
		h.failures++
	}
}

func (c *Cache) now() time.Time { return cachepolicy.Now(c.opts) }

// get fetches and parses a JWKS. Only a 200 JSON object with a "keys" array
// is authoritative; transport errors, other statuses and bodies are
// transient. Malformed, weak or unsupported keys are skipped; an
// authoritative answer without usable keys is an error.
func (c *Cache) get(ctx context.Context, url string) (map[string]crypto.PublicKey, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("jwks_http_%d", resp.StatusCode)
	}
	var doc struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, false, fmt.Errorf("jwks: %w", err)
	}
	var entries []json.RawMessage
	if !bytes.HasPrefix(bytes.TrimSpace(doc.Keys), []byte("[")) || json.Unmarshal(doc.Keys, &entries) != nil {
		return nil, false, errors.New("jwks: response has no keys array")
	}
	// Decode entry by entry, so one malformed key only skips itself.
	var set keys.JWKS
	for _, raw := range entries {
		var j keys.JWK
		if json.Unmarshal(raw, &j) == nil {
			set.Keys = append(set.Keys, j)
		}
	}
	pubs, err := keys.PublicKeys(set)
	return pubs, true, err
}

// Select picks kid's key; an empty kid names the only key.
func Select(keys map[string]crypto.PublicKey, kid string) (crypto.PublicKey, error) {
	key := keys[kid]
	if kid == "" {
		if len(keys) != 1 {
			return nil, errmodel.E(errmodel.CodeMissingKID)
		}
		for _, candidate := range keys {
			key = candidate
		}
	}
	if key == nil {
		return nil, errmodel.E(errmodel.CodeUnknownKID)
	}
	if err := keypolicy.Validate(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Status is one issuer's key-refresh state. Age is the time since the last
// successful fetch (export Age.Seconds() as a gauge); past MaxStale its
// tokens fail with 503 issuer_keys_unavailable (Expired).
type Status struct {
	Issuer    string
	JWKSURI   string
	Keys      int
	Fresh     bool      // keys are within the refresh interval
	FetchedAt time.Time // last successful fetch; zero before the first
	Age       time.Duration
	MaxStale  time.Duration
	Expired   bool      // Age exceeds MaxStale: verification fails closed
	CheckedAt time.Time // last fetch attempt; zero before the first
	Failures  int       // consecutive failed fetches
	LastError string
}

func (c *Cache) pastMaxStale(h *health, now time.Time) bool {
	return h.keys > 0 && now.Sub(h.fetchedAt) > c.opts.MaxStale
}

// Statuses reports every registered issuer, sorted by issuer.
func (c *Cache) Statuses() []Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	out := make([]Status, 0, len(c.health))
	for iss, h := range c.health {
		st := Status{Issuer: iss, JWKSURI: h.is.URL, Keys: h.keys,
			Fresh: h.keys > 0 && now.Sub(h.fetchedAt) < c.opts.RefreshAfter, FetchedAt: h.fetchedAt,
			MaxStale: c.opts.MaxStale, Expired: c.pastMaxStale(h, now), CheckedAt: h.checkedAt, Failures: h.failures}
		if !h.fetchedAt.IsZero() {
			st.Age = now.Sub(h.fetchedAt)
		}
		if h.lastErr != nil {
			st.LastError = h.lastErr.Error()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Issuer < out[j].Issuer })
	return out
}

// Check is a health probe. It reads each issuer a token has needed through
// the cache, so a failing one is retried without token traffic (at most once
// per failure backoff), then fails naming every issuer whose last fetch
// failed, with the age of its keys and whether they are past MaxStale.
func (c *Cache) Check(ctx context.Context) error {
	c.mu.Lock()
	var used []Issuer
	for _, h := range c.health {
		if !h.checkedAt.IsZero() {
			used = append(used, h.is)
		}
	}
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, is := range used {
		wg.Go(func() { _, _ = c.keys.Get(ctx, []Issuer{is}) })
	}
	wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var errs []error
	for iss, h := range c.health {
		switch {
		case h.lastErr == nil:
		case c.pastMaxStale(h, now):
			errs = append(errs, fmt.Errorf("issuer %s keys expired (age %s > max stale %s), verification failing closed: %w",
				iss, now.Sub(h.fetchedAt).Round(time.Second), c.opts.MaxStale, h.lastErr))
		case h.keys > 0:
			errs = append(errs, fmt.Errorf("issuer %s keys stale (age %s, max stale %s): %w",
				iss, now.Sub(h.fetchedAt).Round(time.Second), c.opts.MaxStale, h.lastErr))
		default:
			errs = append(errs, fmt.Errorf("issuer %s has no keys: %w", iss, h.lastErr))
		}
	}
	return errors.Join(errs...)
}
