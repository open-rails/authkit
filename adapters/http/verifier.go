package authhttp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// Verifier validates JWTs from one or more issuers using remote JWKS (verify-only mode).
// It also exposes Optional/Required middleware via adapters/http/middleware.go.
type Verifier struct {
	accept core.AcceptConfig

	httpClient *http.Client

	mu     sync.Mutex
	byIss  map[string]*issuerKeys
	enrich *core.Service
}

type issuerKeys struct {
	jwks       jwtkit.JWKS
	pubByKID   map[string]*rsa.PublicKey
	fetchedAt  time.Time
	expiresAt  time.Time
	staleUntil time.Time
	pinned     *rsa.PublicKey
}

func NewVerifier(accept core.AcceptConfig) *Verifier {
	if len(accept.Algorithms) == 0 {
		accept.Algorithms = []string{"RS256"}
	}
	return &Verifier{
		accept:     accept,
		httpClient: http.DefaultClient,
		byIss:      map[string]*issuerKeys{},
	}
}

// AcceptConfig exposes the accept configuration (used by middleware).
func (v *Verifier) AcceptConfig() core.AcceptConfig { return v.accept }

// WithService enables best-effort enrichment hooks (roles/provider usernames) from Postgres.
func (v *Verifier) WithService(svc *core.Service) *Verifier { v.enrich = svc; return v }

func (v *Verifier) WithHTTPClient(c *http.Client) *Verifier {
	if c != nil {
		v.httpClient = c
	}
	return v
}

func (v *Verifier) JWKS() jwtkit.JWKS { return jwtkit.JWKS{} }

func (v *Verifier) Options() core.Options { return core.Options{} }

func (v *Verifier) ListRoleSlugsByUser(ctx context.Context, userID string) []string {
	if v.enrich == nil {
		return nil
	}
	return v.enrich.ListRoleSlugsByUser(ctx, userID)
}

func (v *Verifier) GetProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	if v.enrich == nil {
		return "", nil
	}
	return v.enrich.GetProviderUsername(ctx, userID, provider)
}

func (v *Verifier) GetEmailByUserID(ctx context.Context, id string) (string, error) {
	if v.enrich == nil {
		return "", nil
	}
	return v.enrich.GetEmailByUserID(ctx, id)
}

func (v *Verifier) Keyfunc() func(token *jwt.Token) (any, error) {
	return func(token *jwt.Token) (any, error) { return v.keyForToken(token) }
}

// Verify parses + verifies a token and enforces issuer/audience/expiry according to AcceptConfig.
func (v *Verifier) Verify(tokenStr string) (jwt.MapClaims, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, errors.New("missing_token")
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, v.Keyfunc())
	if err != nil || tok == nil || !tok.Valid {
		return nil, errors.New("invalid_token")
	}

	iss, _ := claims["iss"].(string)
	match := v.matchIssuer(iss)
	if match == nil {
		return nil, errors.New("bad_issuer")
	}

	var audiences []string
	if len(match.Audiences) > 0 {
		audiences = match.Audiences
	} else if match.Audience != "" {
		audiences = []string{match.Audience}
	}
	if len(audiences) > 0 && !audContainsAny(claims["aud"], audiences) {
		return nil, errors.New("bad_audience")
	}

	skew := v.accept.Skew
	if skew == 0 {
		skew = 60 * time.Second
	}
	now := time.Now()
	expUnix, ok := toUnix(claims["exp"])
	if !ok {
		return nil, errors.New("missing_exp")
	}
	if time.Unix(expUnix, 0).Before(now.Add(-skew)) {
		return nil, errors.New("token_expired")
	}
	if nbfUnix, ok := toUnix(claims["nbf"]); ok {
		if time.Unix(nbfUnix, 0).After(now.Add(skew)) {
			return nil, errors.New("token_not_yet_valid")
		}
	}
	if iatUnix, ok := toUnix(claims["iat"]); ok {
		if time.Unix(iatUnix, 0).After(now.Add(skew)) {
			return nil, errors.New("token_not_yet_valid")
		}
	}

	return claims, nil
}

func (v *Verifier) keyForToken(token *jwt.Token) (any, error) {
	if token == nil {
		return nil, errors.New("nil_token")
	}

	alg, _ := token.Header["alg"].(string)
	if !v.algAllowed(alg) {
		return nil, fmt.Errorf("disallowed_alg")
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	iss, _ := claims["iss"].(string)
	match := v.matchIssuer(iss)
	if match == nil {
		return nil, fmt.Errorf("bad_issuer")
	}

	kid, _ := token.Header["kid"].(string)
	return v.publicKeyFor(context.Background(), *match, kid)
}

func (v *Verifier) matchIssuer(issuer string) *core.IssuerAccept {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil
	}
	for i := range v.accept.Issuers {
		if strings.TrimSpace(v.accept.Issuers[i].Issuer) == issuer {
			return &v.accept.Issuers[i]
		}
	}
	return nil
}

func (v *Verifier) algAllowed(alg string) bool {
	for _, a := range v.accept.Algorithms {
		if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(alg)) {
			return true
		}
	}
	return false
}

func (v *Verifier) publicKeyFor(ctx context.Context, ia core.IssuerAccept, kid string) (*rsa.PublicKey, error) {
	iss := strings.TrimSpace(ia.Issuer)
	if iss == "" {
		return nil, errors.New("bad_issuer")
	}

	cacheTTL := ia.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	maxStale := ia.MaxStale
	if maxStale == 0 {
		maxStale = time.Hour
	}

	v.mu.Lock()
	c := v.byIss[iss]
	if c == nil {
		c = &issuerKeys{}
		if strings.TrimSpace(ia.PinnedRSAPEM) != "" {
			if pk, err := parseRSAPublicKeyFromPEM(ia.PinnedRSAPEM); err == nil {
				c.pinned = pk
			}
		}
		v.byIss[iss] = c
	}
	now := time.Now()
	shouldFetch := c.pubByKID == nil || now.After(c.expiresAt)
	hasFresh := c.pubByKID != nil && now.Before(c.expiresAt)
	hasStale := c.pubByKID != nil && now.Before(c.staleUntil)
	v.mu.Unlock()

	if shouldFetch {
		if err := v.refreshIssuerKeys(ctx, iss, ia, cacheTTL, maxStale); err != nil && !hasStale && !hasFresh {
			// Hard failure and no usable cache: fall back to pinned key if available.
			if c.pinned != nil {
				return c.pinned, nil
			}
			return nil, err
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if kid != "" {
		if pk := c.pubByKID[kid]; pk != nil {
			return pk, nil
		}
		// Unknown key id: allow pinned key if configured.
		if c.pinned != nil {
			return c.pinned, nil
		}
		return nil, errors.New("unknown_kid")
	}
	// No kid: if exactly one key is present, use it.
	if len(c.pubByKID) == 1 {
		for _, pk := range c.pubByKID {
			return pk, nil
		}
	}
	if c.pinned != nil {
		return c.pinned, nil
	}
	return nil, errors.New("missing_kid")
}

func (v *Verifier) refreshIssuerKeys(ctx context.Context, issuer string, ia core.IssuerAccept, cacheTTL, maxStale time.Duration) error {
	jwksURL := strings.TrimSpace(ia.JWKSURL)
	if jwksURL == "" {
		jwksURL = strings.TrimRight(strings.TrimSpace(issuer), "/") + "/.well-known/jwks.json"
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks_http_%d", resp.StatusCode)
	}

	var ks jwtkit.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return err
	}
	pubByKID, err := jwksToRSAPublicKeys(ks)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	c := v.byIss[issuer]
	if c == nil {
		c = &issuerKeys{}
		v.byIss[issuer] = c
	}
	now := time.Now()
	c.jwks = ks
	c.pubByKID = pubByKID
	c.fetchedAt = now
	c.expiresAt = now.Add(cacheTTL)
	c.staleUntil = now.Add(cacheTTL + maxStale)
	return nil
}

func jwksToRSAPublicKeys(ks jwtkit.JWKS) (map[string]*rsa.PublicKey, error) {
	out := map[string]*rsa.PublicKey{}
	for _, k := range ks.Keys {
		if !strings.EqualFold(k.Kty, "RSA") {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() {
			return nil, errors.New("bad_rsa_exponent")
		}
		pk := &rsa.PublicKey{N: n, E: int(e.Int64())}
		kid := strings.TrimSpace(k.Kid)
		if kid == "" {
			kid = "default"
		}
		out[kid] = pk
	}
	if len(out) == 0 {
		return nil, errors.New("empty_jwks")
	}
	return out, nil
}

func parseRSAPublicKeyFromPEM(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("bad_pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Some PEMs may encode a full certificate.
		if cert, err2 := x509.ParseCertificate(block.Bytes); err2 == nil {
			pub = cert.PublicKey
			err = nil
		}
		if err != nil {
			return nil, err
		}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not_rsa")
	}
	return rsaPub, nil
}
