package securitytest

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestSecurityLimiterOutageStaysLimited: a Redis outage never lifts a budget
// or splits it per process. While the limiter's Redis stops answering or
// refuses connections, replicas spend the same budgets in PostgreSQL, a
// request waits on Redis only a moment whatever the client's timeouts, and a
// 429 still says when to retry. Once Redis answers again, budgets are spent
// there again.
func TestSecurityLimiterOutageStaysLimited(t *testing.T) {
	link, rdb := newRedisLink(t)
	h := newHost(t, withHTTP(func(c *authkit.HTTPConfig) {
		c.RateLimits = map[string]authkit.RateLimit{
			"password_login":        {Limit: 3, Window: time.Hour},
			"register_availability": {Limit: 3, Window: time.Hour},
		}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.Redis = rdb
		d.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Client") }
	}))
	b := h.replica()
	a := h.newAccount("outage")
	login := func(on *host, address string) response {
		return on.do(request{method: http.MethodPost, path: "/password/login", header: http.Header{"X-Client": {address}},
			body: map[string]string{"identifier": a.email, "password": "wrong-" + password}})
	}
	availability := func(on *host, address string) response {
		return on.do(request{method: http.MethodGet, path: "/register/availability?username=" + unique("free"), header: http.Header{"X-Client": {address}}})
	}
	// spend sends three requests through the given replicas in turn, each
	// answered with status, and requires the fourth refused.
	spend := func(t *testing.T, send func(*host) response, status int, replicas ...*host) {
		t.Helper()
		for i := range 3 {
			resp := send(replicas[i%len(replicas)])
			require.Equal(t, status, resp.status, "request %d: %s", i+1, resp)
		}
		resp := send(replicas[3%len(replicas)])
		require.Equal(t, http.StatusTooManyRequests, resp.status, "the budget was lifted: %s", resp)
		require.Equal(t, "rate_limited", resp.errorCode())
		retry, err := strconv.Atoi(resp.header.Get("Retry-After"))
		require.NoError(t, err, "a 429 without Retry-After")
		require.Positive(t, retry)
		require.Equal(t, "3", resp.header.Get("RateLimit-Limit"))
		require.Equal(t, "0", resp.header.Get("RateLimit-Remaining"))
	}
	loginFrom := func(address string) func(*host) response {
		return func(on *host) response { return login(on, address) }
	}

	t.Run("replicas share budgets through Redis", func(t *testing.T) {
		spend(t, loginFrom("203.0.113.1"), http.StatusUnauthorized, h, b)
	})

	t.Run("a Redis that stops answering costs a moment, and replicas share budgets in PostgreSQL", func(t *testing.T) {
		link.set(linkStalled)
		started := time.Now()
		spend(t, loginFrom("203.0.113.2"), http.StatusUnauthorized, h, b)
		require.Less(t, time.Since(started), 5*time.Second, "requests waited on the stalled Redis")
		spend(t, func(on *host) response { return availability(on, "203.0.113.2") }, http.StatusOK, h, b)
	})

	t.Run("a Redis that refuses connections leaves every budget shared", func(t *testing.T) {
		link.set(linkCut)
		spend(t, loginFrom("203.0.113.3"), http.StatusUnauthorized, b, h)
		spend(t, func(on *host) response { return availability(on, "203.0.113.3") }, http.StatusOK, b, h)
	})

	t.Run("budgets are shared again once Redis answers", func(t *testing.T) {
		link.set(linkUp)
		for _, on := range []*host{h, b} {
			require.Eventually(t, func() bool {
				address := unique("probe")
				login(on, address)
				keys, err := rdb.Keys(t.Context(), "*:ip:"+address+":*").Result()
				return err == nil && len(keys) == 1
			}, 45*time.Second, 100*time.Millisecond, "a replica never went back to Redis")
		}
		spend(t, loginFrom("203.0.113.4"), http.StatusUnauthorized, h, b)
	})
}

// TestSecurityReplicasShareRateLimits: two AuthKit instances on one database,
// each with its own pool, spend one budget without Redis and with a declared
// Redis that is down: the request past the limit is refused whichever
// instance it reaches.
func TestSecurityReplicasShareRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		redis func(t *testing.T) *redis.Client
	}{
		{name: "without Redis"},
		{name: "with a declared Redis that is down", redis: refusedRedis},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			deps := authtest.WithDeps(func(d *authkit.Deps) {
				if tc.redis != nil {
					d.Redis = tc.redis(t)
				}
			})
			one := newHost(t, withHTTP(func(c *authkit.HTTPConfig) {
				c.RateLimits = map[string]authkit.RateLimit{"password_login": {Limit: 3, Window: time.Hour}}
			}), deps)
			two := one.replica(ownPool(t, one.pool), deps)
			a := one.newAccount("shared-limits")
			login := func(on *host) response {
				return on.post("/password/login", map[string]string{"identifier": a.email, "password": "wrong-" + password}, "")
			}
			for i, on := range []*host{one, two, one} {
				resp := login(on)
				require.Equal(t, http.StatusUnauthorized, resp.status, "request %d: %s", i+1, resp)
			}
			for _, on := range []*host{two, one} {
				resp := login(on)
				require.Equal(t, http.StatusTooManyRequests, resp.status, "an instance kept its own budget: %s", resp)
				require.Equal(t, "rate_limited", resp.errorCode())
				retry, err := strconv.Atoi(resp.header.Get("Retry-After"))
				require.NoError(t, err)
				require.Positive(t, retry)
				require.Equal(t, "0", resp.header.Get("RateLimit-Remaining"))
			}
			var rows int
			require.NoError(t, one.pool.QueryRow(t.Context(), `SELECT count(*) FROM profiles.rate_limits WHERE key LIKE 'password_login:%'`).Scan(&rows))
			require.Equal(t, 1, rows, "the budget is one PostgreSQL row")
			if tc.redis != nil {
				require.Contains(t, logs.String(), "budgets are spent in PostgreSQL until Redis recovers")
			}
			require.NotContains(t, logs.String(), "per-process")
		})
	}
}

// refusedRedis is a client of a Redis that is down: nothing listens on its
// address.
func refusedRedis(t *testing.T) *redis.Client {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	client := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// ownPool gives a replica its own pool on the host's database.
func ownPool(t *testing.T, shared *pgxpool.Pool) authtest.Option {
	pool, err := pgxpool.New(context.Background(), shared.Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = pool })
}

type linkMode int

const (
	linkUp linkMode = iota
	linkStalled
	linkCut
)

// redisLink is the network between AuthKit and a real Redis. Stalled, it
// accepts connections and never answers; cut, it closes them as a stopped
// server does.
type redisLink struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	mode   linkMode
	conns  []net.Conn
}

// newRedisLink returns a client of a scratch Redis whose connections all pass
// through the link. The client's own timeouts are long, so only AuthKit's
// bound keeps an outage from stalling requests.
func newRedisLink(t *testing.T) (*redisLink, *redis.Client) {
	t.Helper()
	direct := testdb.ScratchRedis(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := &redisLink{ln: ln, target: direct.Options().Addr}
	go l.serve()
	opts := *direct.Options()
	opts.Addr, opts.ReadTimeout, opts.WriteTimeout = ln.Addr().String(), 30*time.Second, 30*time.Second
	client := redis.NewClient(&opts)
	t.Cleanup(func() {
		_ = ln.Close()
		l.set(linkCut)
		_ = client.Close()
	})
	return l, client
}

func (l *redisLink) serve() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.mu.Lock()
		switch l.mode {
		case linkCut:
			_ = c.Close()
		case linkStalled:
			l.conns = append(l.conns, c)
		default:
			up, err := net.Dial("tcp", l.target)
			if err != nil {
				_ = c.Close()
				break
			}
			l.conns = append(l.conns, c, up)
			go pipe(c, up)
			go pipe(up, c)
		}
		l.mu.Unlock()
	}
}

func pipe(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}

// set switches the link's mode and drops every connection it carries.
func (l *redisLink) set(mode linkMode) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.mode = mode
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

// TestSecurityUnknownClientAddressIsLimited: a request whose client address
// cannot be determined is never exempt from the per-address budget. Every such
// request shares one budget, and AuthKit warns once that what sits in front of
// it is misdeclared.
func TestSecurityUnknownClientAddressIsLimited(t *testing.T) {
	logs := captureLogs(t)
	h := newHost(t, withHTTP(func(c *authkit.HTTPConfig) {
		c.DirectPeerIP = false
		c.RateLimits = map[string]authkit.RateLimit{"password_login": {Limit: 3, Window: time.Hour}}
	}), authtest.WithDeps(func(d *authkit.Deps) { d.ClientIP = func(*http.Request) string { return "" } }))
	a := h.newAccount("noaddress")
	for range 3 {
		resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": "wrong-" + password}, "")
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
	}
	resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	require.Equal(t, http.StatusTooManyRequests, resp.status, "requests without an address went unlimited: %s", resp)
	require.Equal(t, 1, strings.Count(logs.String(), "a request has no client address"), logs.String())
}
