// Package jwks is the issuer key cache behind every AuthKit verifier: it
// fetches an issuer's JWKS, serves it stale-while-revalidate up to a max
// staleness, refetches on key rotation, and reports health. Public verify
// uses it for the issuers a host adds; the engine for remote applications.
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

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/keypolicy"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/keys"
)

// Default cache policy.
const (
	DefaultTTL      = 10 * time.Minute
	DefaultMaxStale = 4 * time.Hour
)

// Issuer is one issuer's JWKS endpoint and cache policy.
type Issuer struct {
	Issuer string
	URL    string
	// TTL is how long fetched keys are fresh (default 10m).
	TTL time.Duration
	// MaxStale bounds how long after the last successful fetch keys keep
	// verifying while refreshes fail, so a peer's revocation cannot be
	// suppressed by blocking the fetch (default 4h, never below TTL).
	MaxStale time.Duration
}

func (is Issuer) ttl() time.Duration      { return cmp.Or(is.TTL, DefaultTTL) }
func (is Issuer) maxStale() time.Duration { return max(cmp.Or(is.MaxStale, DefaultMaxStale), is.ttl()) }

// Cache holds fetched keys per issuer. Every count in it is bounded by the
// issuers its owner registered, never by request traffic.
type Cache struct {
	client *http.Client

	mu      sync.RWMutex
	entries map[string]*entry

	// AttemptTimeout bounds one fetch; a failing issuer is retried in the
	// background with capped full-jitter backoff. RefetchMin spaces the
	// refetches an unknown kid or bad signature forces. Now is the clock.
	AttemptTimeout          time.Duration
	BackoffBase, BackoffMax time.Duration
	RefetchMin              time.Duration
	Now                     func() time.Time
}

// entry is one issuer's keys: served past expiresAt while a single background
// loop refetches them, until maxStale after fetchedAt.
type entry struct {
	is        Issuer
	keys      map[string]crypto.PublicKey
	expiresAt time.Time
	fetchedAt time.Time

	// fetchSeq numbers fetches as they start; appliedSeq is the newest whose
	// result was recorded, so a slower older fetch never overwrites it.
	fetchSeq, appliedSeq uint64

	refreshing bool
	attempted  chan struct{} // closed after the running loop's first attempt
	checkedAt  time.Time
	lastErr    error
	failures   int

	refetchAt     time.Time
	refetchFlight chan struct{}
}

// New returns a cache fetching with client (nil: a timeout-bounded client
// that may reach private addresses).
func New(client *http.Client) *Cache {
	if client == nil {
		client = netguard.Client(netguard.DefaultTimeout, true)
	}
	return &Cache{
		client:         client,
		entries:        map[string]*entry{},
		AttemptTimeout: 3 * time.Second,
		BackoffBase:    500 * time.Millisecond,
		BackoffMax:     30 * time.Second,
		RefetchMin:     30 * time.Second,
		Now:            time.Now,
	}
}

// Drop forgets iss's keys.
func (c *Cache) Drop(iss string) {
	c.mu.Lock()
	delete(c.entries, iss)
	c.mu.Unlock()
}

// entryLocked is iss's entry for is, replaced when its endpoint or policy
// changed. Caller holds c.mu.
func (c *Cache) entryLocked(is Issuer) *entry {
	e := c.entries[is.Issuer]
	if e == nil || e.is != is {
		e = &entry{is: is}
		c.entries[is.Issuer] = e
	}
	return e
}

// Key returns the key kid names from is's JWKS. A request waits only when the
// issuer has no usable keys, and then for at most one bounded attempt; an
// unknown kid on a healthy issuer forces one throttled refetch (rotation).
func (c *Cache) Key(ctx context.Context, is Issuer, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	e := c.entryLocked(is)
	now := c.Now()
	keys := e.usableLocked(now)
	if len(keys) == 0 || now.After(e.expiresAt) {
		c.startRefreshLocked(e)
	}
	attempted, lastErr := e.attempted, e.lastErr
	c.mu.Unlock()
	if len(keys) == 0 {
		select {
		case <-attempted:
		case <-ctx.Done():
		}
		c.mu.RLock()
		keys, lastErr = e.usableLocked(c.Now()), e.lastErr
		c.mu.RUnlock()
		if len(keys) == 0 {
			return nil, unavailable(cmp.Or(lastErr, ctx.Err(), errPastMaxStale))
		}
		return Select(keys, kid)
	}
	key, err := Select(keys, kid)
	if err == nil || kid == "" {
		return key, err
	}
	// While the issuer is failing, the background loop owns refetching.
	if lastErr != nil {
		return nil, unavailable(lastErr)
	}
	if c.refetch(ctx, e) {
		c.mu.RLock()
		keys = e.usableLocked(c.Now())
		c.mu.RUnlock()
		key, err = Select(keys, kid)
	}
	return key, err
}

// Refresh forces one throttled refetch of a healthy issuer's keys after a
// signature failed under them: a rotated key that kept its kid. It reports
// whether a refetch ran, so the caller retries once.
func (c *Cache) Refresh(ctx context.Context, is Issuer) bool {
	c.mu.RLock()
	e := c.entries[is.Issuer]
	healthy := e != nil && e.is == is && e.lastErr == nil
	c.mu.RUnlock()
	return healthy && c.refetch(ctx, e)
}

var errPastMaxStale = errors.New("cached keys exceed max stale")

func unavailable(cause error) error {
	return errmodel.E(errmodel.CodeIssuerKeysUnavailable, errmodel.WithCause(cause))
}

func (e *entry) usableLocked(now time.Time) map[string]crypto.PublicKey {
	if e.pastMaxStale(now) {
		return nil
	}
	return e.keys
}

func (e *entry) pastMaxStale(now time.Time) bool {
	return len(e.keys) > 0 && now.Sub(e.fetchedAt) > e.is.maxStale()
}

// startRefreshLocked starts e's background refresh loop unless one runs.
func (c *Cache) startRefreshLocked(e *entry) {
	if e.refreshing {
		return
	}
	e.refreshing, e.attempted = true, make(chan struct{})
	go c.refreshLoop(e, e.attempted)
}

// refreshLoop refetches until an attempt succeeds or e is replaced, sleeping
// with capped full-jitter backoff between failures.
func (c *Cache) refreshLoop(e *entry, attempted chan struct{}) {
	for attempt := 0; ; attempt++ {
		err := c.fetch(context.Background(), e)
		if attempt == 0 {
			close(attempted)
		}
		c.mu.Lock()
		done := err == nil || c.entries[e.is.Issuer] != e
		if done {
			e.refreshing = false
		}
		c.mu.Unlock()
		if done {
			return
		}
		time.Sleep(netguard.Backoff(attempt, c.BackoffBase, c.BackoffMax))
	}
}

// refetch runs one synchronous fetch, single-flighted and at most once per
// RefetchMin, so a storm of bad kids or signatures cannot hammer the
// endpoint. A failed refetch hands the issuer to the background loop.
func (c *Cache) refetch(ctx context.Context, e *entry) bool {
	c.mu.Lock()
	if done := e.refetchFlight; done != nil {
		c.mu.Unlock()
		select {
		case <-done:
			return true
		case <-ctx.Done():
			return false
		}
	}
	if !e.refetchAt.IsZero() && c.Now().Sub(e.refetchAt) < c.RefetchMin {
		c.mu.Unlock()
		return false
	}
	done := make(chan struct{})
	e.refetchFlight = done
	c.mu.Unlock()

	err := c.fetch(context.WithoutCancel(ctx), e)

	c.mu.Lock()
	e.refetchAt, e.refetchFlight = c.Now(), nil
	close(done)
	if err != nil && c.entries[e.is.Issuer] == e {
		c.startRefreshLocked(e)
	}
	c.mu.Unlock()
	return true
}

// fetch runs one bounded fetch and records its outcome: a transient failure
// keeps the cached keys (bounded by MaxStale); an authoritative JWKS replaces
// them, and one with no usable keys drops them (fail closed).
func (c *Cache) fetch(ctx context.Context, e *entry) error {
	c.mu.Lock()
	e.fetchSeq++
	seq := e.fetchSeq
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, c.AttemptTimeout)
	defer cancel()
	keys, authoritative, err := c.get(ctx, e.is.URL)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[e.is.Issuer] != e {
		// A replacement owns the issuer now; never publish an old endpoint's keys.
		return errors.New("issuer keys changed during refresh")
	}
	if seq < e.appliedSeq {
		return e.lastErr // a newer fetch already recorded its result
	}
	e.appliedSeq = seq
	e.checkedAt, e.lastErr = c.Now(), err
	switch {
	case err == nil:
		e.keys, e.fetchedAt, e.expiresAt, e.failures = keys, e.checkedAt, e.checkedAt.Add(e.is.ttl()), 0
	case authoritative:
		e.keys = nil
		e.failures++
	default:
		e.failures++
	}
	return err
}

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
	Fresh     bool      // keys are within the cache TTL
	FetchedAt time.Time // last successful fetch; zero before the first
	Age       time.Duration
	MaxStale  time.Duration
	Expired   bool      // Age exceeds MaxStale: verification fails closed
	CheckedAt time.Time // last fetch attempt; zero before the first
	Failures  int       // consecutive failed fetches
	LastError string
}

// Statuses reports every issuer, sorted by issuer.
func (c *Cache) Statuses() []Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.Now()
	out := make([]Status, 0, len(c.entries))
	for iss, e := range c.entries {
		st := Status{Issuer: iss, JWKSURI: e.is.URL, Keys: len(e.keys),
			Fresh: len(e.keys) > 0 && now.Before(e.expiresAt), FetchedAt: e.fetchedAt,
			MaxStale: e.is.maxStale(), Expired: e.pastMaxStale(now), CheckedAt: e.checkedAt, Failures: e.failures}
		if !e.fetchedAt.IsZero() {
			st.Age = now.Sub(e.fetchedAt)
		}
		if e.lastErr != nil {
			st.LastError = e.lastErr.Error()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Issuer < out[j].Issuer })
	return out
}

// Check is a no-I/O health probe: it fails naming every issuer whose last
// fetch failed, with the age of its keys and whether they are past MaxStale.
func (c *Cache) Check() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.Now()
	var errs []error
	for iss, e := range c.entries {
		switch {
		case e.lastErr == nil:
		case e.pastMaxStale(now):
			errs = append(errs, fmt.Errorf("issuer %s keys expired (age %s > max stale %s), verification failing closed: %w",
				iss, now.Sub(e.fetchedAt).Round(time.Second), e.is.maxStale(), e.lastErr))
		case len(e.keys) > 0:
			errs = append(errs, fmt.Errorf("issuer %s keys stale (age %s, max stale %s): %w",
				iss, now.Sub(e.fetchedAt).Round(time.Second), e.is.maxStale(), e.lastErr))
		default:
			errs = append(errs, fmt.Errorf("issuer %s has no keys: %w", iss, e.lastErr))
		}
	}
	return errors.Join(errs...)
}
