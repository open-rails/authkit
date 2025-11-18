package authgin

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// Verifier validates JWTs against configured issuers and JWKS, without mounting any routes.
type Verifier struct {
	accept core.AcceptConfig
	http   *http.Client
	mu     sync.RWMutex
	byIss  map[string]*jwksCache
	algs   map[string]struct{}
	skew   time.Duration
	svc    *core.Service
}

type jwksCache struct {
	url      string
	pinned   *rsa.PublicKey
	cacheTTL time.Duration
	maxStale time.Duration

	mu      sync.RWMutex
	pubs    map[string]*rsa.PublicKey // kid -> pub
	fetched time.Time
}

func NewVerifier(accept core.AcceptConfig) *Verifier {
	v := &Verifier{
		accept: accept,
		http:   &http.Client{Timeout: 5 * time.Second},
		byIss:  map[string]*jwksCache{},
		algs:   map[string]struct{}{"RS256": {}},
		skew:   60 * time.Second,
	}
	if accept.Skew > 0 {
		v.skew = accept.Skew
	}
	if len(accept.Algorithms) > 0 {
		v.algs = map[string]struct{}{}
		for _, a := range accept.Algorithms {
			v.algs[a] = struct{}{}
		}
	}
	for _, iss := range accept.Issuers {
		url := iss.JWKSURL
		if strings.TrimSpace(url) == "" {
			url = strings.TrimRight(iss.Issuer, "/") + "/.well-known/jwks.json"
		}
		jc := &jwksCache{
			url:      url,
			pubs:     map[string]*rsa.PublicKey{},
			cacheTTL: ifOr(iss.CacheTTL, 15*time.Minute),
			maxStale: ifOr(iss.MaxStale, time.Hour),
		}
		if strings.TrimSpace(iss.PinnedRSAPEM) != "" {
			if pk, err := parseRSAPEM(iss.PinnedRSAPEM); err == nil {
				jc.pinned = pk
			}
		}
		v.byIss[iss.Issuer] = jc
	}
	return v
}

// WithService attaches a core.Service as a RoleStore (DB-backed enrichment).
func (v *Verifier) WithService(s *core.Service) *Verifier { v.svc = s; return v }

func ifOr(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func parseRSAPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("bad_pem")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not_rsa")
	}
	return pk, nil
}

type jwksDoc struct {
	Keys []struct{ Kty, Kid, Alg, Use, N, E string } `json:"keys"`
}

func (j *jwksCache) get(kid string, cli *http.Client) (*rsa.PublicKey, error) {
	j.mu.RLock()
	pub := j.pubs[kid]
	fetched := j.fetched
	j.mu.RUnlock()
	if pub != nil && time.Since(fetched) < j.cacheTTL {
		return pub, nil
	}

	var err error
	// fetch/refresh
	if err = j.refresh(cli); err == nil {
		j.mu.RLock()
		pub = j.pubs[kid]
		j.mu.RUnlock()
		if pub != nil {
			return pub, nil
		}
	}

	// fallback to pinned if present and within max-stale
	if j.pinned != nil && time.Since(fetched) < j.maxStale {
		return j.pinned, nil
	}
	if j.pinned != nil && fetched.IsZero() {
		return j.pinned, nil
	}

	logrus.WithError(err).WithField("issuer", j.url).Error("jwks_fetch_failed")
	return nil, errors.New("key_not_found")
}

func (j *jwksCache) refresh(cli *http.Client) error {
	req, _ := http.NewRequest(http.MethodGet, j.url, nil)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return errors.New("jwks_http")
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	m := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if strings.ToUpper(k.Kty) != "RSA" {
			continue
		}
		// n,e are base64url without padding
		nBytes, eBytes := b64url(k.N), b64url(k.E)
		if len(nBytes) == 0 || len(eBytes) == 0 {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e*256 + int(b)
		}
		pk := &rsa.PublicKey{N: n, E: e}
		m[k.Kid] = pk
	}
	j.mu.Lock()
	j.pubs = m
	j.fetched = time.Now()
	j.mu.Unlock()
	return nil
}

// no custom big-int wrapper; math/big is used directly

// b64url decodes base64url without padding.
func b64url(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

// Verify parses and validates a JWT string and returns its claims.
func (v *Verifier) Verify(tokenStr string) (jwt.MapClaims, error) {
	if strings.TrimSpace(tokenStr) == "" {
		return nil, errors.New("missing_token")
	}
	var claims jwt.MapClaims
	keyfunc := func(tok *jwt.Token) (any, error) {
		// alg check
		if _, ok := v.algs[tok.Method.Alg()]; !ok {
			return nil, errors.New("bad_alg")
		}
		// issuer from payload (untrusted until verified), but used to select JWKS
		issAny, ok := tok.Claims.(jwt.MapClaims)["iss"]
		if !ok {
			return nil, errors.New("bad_issuer")
		}
		iss, _ := issAny.(string)
		v.mu.RLock()
		jc := v.byIss[iss]
		v.mu.RUnlock()
		if jc == nil {
			return nil, errors.New("bad_issuer")
		}
		kid, _ := tok.Header["kid"].(string)
		if kid == "" {
			if jc.pinned != nil {
				return jc.pinned, nil
			}
			return nil, errors.New("missing_kid")
		}
		return jc.get(kid, v.http)
	}
	tok, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, keyfunc, jwt.WithLeeway(v.skew))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid_token: %w", err)
	}
	// iss/aud enforcement
	claims, _ = tok.Claims.(jwt.MapClaims)
	iss := stringVal(claims["iss"])
	v.mu.RLock()
	ia := v.byIss[iss]
	v.mu.RUnlock()
	if ia == nil {
		return nil, errors.New("bad_issuer")
	}
	expectedAud := acceptAudience(v.accept, iss)
	if expectedAud != "" && !audContains(claims["aud"], expectedAud) {
		return nil, errors.New("bad_audience")
	}
	return claims, nil
}

func (v *Verifier) MiddlewareRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := ginutil.BearerToken(c.GetHeader("Authorization"))
		if tokenStr == "" {
			ginutil.Unauthorized(c, "missing_token")
			return
		}
		claims, err := v.Verify(tokenStr)
		if err != nil {
			ginutil.Unauthorized(c, err.Error())
			return
		}
		attachClaimsToContext(c, claims)
		if v.svc != nil {
			enrichWithDB(c, v.svc)
		} else {
			attachTypedClaims(c, claims)
		}
		c.Next()
	}
}

func (v *Verifier) MiddlewareOptional() gin.HandlerFunc {
	req := v.MiddlewareRequired()
	return func(c *gin.Context) {
		if ginutil.BearerToken(c.GetHeader("Authorization")) == "" {
			c.Next()
			return
		}
		req(c)
	}
}

// helpers
func attachTypedClaims(c *gin.Context, claims jwt.MapClaims) {
	roles := toStringSlice(claims["roles"])
	if len(roles) > 0 {
		c.Set("auth.roles", roles)
	}
	ents := toStringSlice(claims["entitlements"])
	if len(ents) > 0 {
		c.Set("auth.entitlements", ents)
	}
	cl := Claims{UserID: stringVal(claims["sub"]), Email: stringVal(claims["email"]), Roles: roles, Entitlements: ents}
	c.Set("authkit.claims", cl)
	c.Request = c.Request.WithContext(SetClaims(c.Request.Context(), cl))
}
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
func stringVal(v any) string { s, _ := v.(string); return s }
func audFrom(cl jwt.MapClaims) []string {
	switch a := cl["aud"].(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return a
	}
	return nil
}
func acceptAudience(ac core.AcceptConfig, iss string) string {
	for _, i := range ac.Issuers {
		if i.Issuer == iss {
			return i.Audience
		}
	}
	return ""
}
func acceptedAud(want []string, got []string) []string {
	if len(want) == 0 {
		return got
	}
	set := map[string]struct{}{}
	for _, w := range want {
		set[w] = struct{}{}
	}
	out := []string{}
	for _, g := range got {
		if _, ok := set[g]; ok {
			out = append(out, g)
		}
	}
	return out
}

func attachClaimsToContext(c *gin.Context, claims jwt.MapClaims) {
	if sub, _ := claims["sub"].(string); sub != "" {
		c.Set("auth.user_id", sub)
	}
	if em, _ := claims["email"].(string); em != "" {
		c.Set("auth.email", em)
	}
	if un, _ := claims["username"].(string); un != "" {
		c.Set("auth.username", un)
	}
	if du, _ := claims["discord_username"].(string); du != "" {
		c.Set("auth.discord_username", du)
	}
	// note: we only attach typed Claims via "authkit.claims"; no raw JWT claims stored
}

// DB-backed enrichment using RoleStore
// (roleStore path removed; we enrich directly with *core.Service)

// enrichWithDB fetches roles and canonical email from DB and sets typed claims.
func enrichWithDB(c *gin.Context, svc *core.Service) {
	uidVal, _ := c.Get("auth.user_id")
	uid, _ := uidVal.(string)
	email, _ := svc.GetEmailByUserID(c.Request.Context(), uid)
	roles := svc.ListRoleSlugsByUser(c.Request.Context(), uid)
	if len(roles) > 0 {
		c.Set("auth.roles", roles)
	}
	cl := Claims{UserID: uid, Email: email, Roles: roles}
	if un, ok := c.Get("auth.username"); ok {
		if s, ok2 := un.(string); ok2 {
			cl.Username = s
		}
	}
	c.Set("authkit.claims", cl)
	c.Request = c.Request.WithContext(SetClaims(c.Request.Context(), cl))
}
