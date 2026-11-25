// Package dpop verifies the ES256/P-256 profile of RFC 9449 sender proofs.
// Proofs establish possession of a key, never user identity or authorization.
package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/jws"
)

var (
	ErrInvalidProof      = errors.New("invalid DPoP proof")
	ErrReplay            = errors.New("DPoP proof already used")
	ErrReplayUnavailable = errors.New("DPoP replay protection unavailable")
	// ErrNonceRequired refuses an otherwise valid proof without a current
	// server nonce (RFC 9449 §8); the client retries with a fresh one.
	ErrNonceRequired = errors.New("DPoP nonce required")
)

// ReplayGuard atomically claims key until ttl elapses. It returns true only
// for the first claim. All receiver replicas must share the same store. Errors
// must fail closed; implementations must not evict live claims to admit others.
// Keys are fixed-size SHA-256 digests; ttl is at most 121 seconds.
type ReplayGuard func(ctx context.Context, key string, ttl time.Duration) (bool, error)

// Check is what a proof must match.
type Check struct {
	// URL is the trusted request URL: from server configuration or trusted
	// routing, never unvalidated forwarding headers.
	URL string
	// AccessToken is the token the proof must hash (ath); "" at a token
	// endpoint, where a proof carries none.
	AccessToken string
	// Thumbprint is the bound token's cnf.jkt; "" binds a new token to the
	// proof's key.
	Thumbprint string
	Replay     ReplayGuard
	// Nonces, when set, requires a current server nonce.
	Nonces NonceSource
}

// Verify verifies exactly one DPoP header against c and the request method,
// and returns the proof key's RFC 7638 thumbprint (unpadded base64url). Call
// only after authenticating the access token.
func Verify(r *http.Request, c Check) (string, error) {
	const zero = ""
	if r == nil || len(c.AccessToken) > 32<<10 || len(r.Header.Values("DPoP")) != 1 {
		return zero, ErrInvalidProof
	}
	proof := r.Header.Get("DPoP")
	if len(proof) > 4<<10 {
		return zero, ErrInvalidProof
	}
	parsed, err := jws.Parse(proof)
	if err != nil || len(parsed.Header) != 3 || jws.String(parsed.Header["typ"]) != "dpop+jwt" {
		return zero, ErrInvalidProof
	}
	thumbprint, err := parsed.VerifyEmbeddedES256()
	if err != nil {
		return zero, ErrInvalidProof
	}
	claims := parsed.Claims
	jti := jws.String(claims["jti"])
	if len(jti) < 16 || len(jti) > 128 || strings.ContainsAny(jti, " \t\r\n") || jws.String(claims["htm"]) != r.Method {
		return zero, ErrInvalidProof
	}
	proofURL := jws.String(claims["htu"])
	target, err := url.Parse(proofURL)
	if err != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || strings.Contains(proofURL, "#") {
		return zero, ErrInvalidProof
	}
	wantURL, err := canonicalURL(c.URL)
	if err != nil {
		return zero, ErrInvalidProof
	}
	gotURL, err := canonicalURL(proofURL)
	if err != nil || gotURL != wantURL {
		return zero, ErrInvalidProof
	}
	var iat int64
	if err := json.Unmarshal(claims["iat"], &iat); err != nil {
		return zero, ErrInvalidProof
	}
	now := time.Now()
	if iat < now.Unix()-60 || iat > now.Unix()+60 {
		return zero, ErrInvalidProof
	}
	if c.AccessToken == "" {
		if _, ok := claims["ath"]; ok {
			return zero, ErrInvalidProof
		}
	} else if ath := sha256.Sum256([]byte(c.AccessToken)); jws.String(claims["ath"]) != base64.RawURLEncoding.EncodeToString(ath[:]) {
		return zero, ErrInvalidProof
	}
	if c.Thumbprint != "" && c.Thumbprint != thumbprint {
		return zero, ErrInvalidProof
	}
	if c.Nonces != nil && !c.Nonces.Valid(r.Context(), jws.String(claims["nonce"])) {
		return zero, ErrNonceRequired
	}
	if c.Replay == nil {
		return zero, ErrReplayUnavailable
	}
	sum, _ := base64.RawURLEncoding.DecodeString(thumbprint)
	replayKey := sha256.Sum256(append(sum, []byte(jti)...))
	// Round up to whole seconds so millisecond-resolution stores cannot expire
	// a replay claim just before the last accepted fractional second.
	ttl := time.Duration(iat+61-now.Unix()) * time.Second
	claimed, err := c.Replay(r.Context(), base64.RawURLEncoding.EncodeToString(replayKey[:]), ttl)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrReplayUnavailable, err)
	}
	if !claimed {
		return zero, ErrReplay
	}
	return thumbprint, nil
}

func canonicalURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" {
		return "", ErrInvalidProof
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return "", ErrInvalidProof
		}
	}
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	path := normalizePath(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	return u.Scheme + "://" + u.Host + path, nil
}

// normalizePath is RFC 3986 §6.2.2's syntax-based normalization of an escaped
// path, which RFC 9449 §4.3 asks for before comparing htu: percent-encodings
// in upper case, unreserved characters decoded, dot segments removed.
func normalizePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if c := p[i]; c != '%' || i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
			b.WriteByte(c)
			continue
		}
		v := unhex(p[i+1])<<4 | unhex(p[i+2])
		if 'a' <= v && v <= 'z' || 'A' <= v && v <= 'Z' || '0' <= v && v <= '9' || strings.IndexByte("-._~", v) >= 0 {
			b.WriteByte(v)
		} else {
			b.WriteString(strings.ToUpper(p[i : i+3]))
		}
		i += 2
	}
	return removeDotSegments(b.String())
}

// removeDotSegments is RFC 3986 §5.2.4 for an absolute path.
func removeDotSegments(p string) string {
	if !strings.HasPrefix(p, "/") || !strings.Contains(p, ".") {
		return p
	}
	segments := strings.Split(p[1:], "/")
	out := make([]string, 0, len(segments))
	for i, s := range segments {
		last := i == len(segments)-1
		switch s {
		case ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
			continue
		}
		if last {
			out = append(out, "")
		}
	}
	return "/" + strings.Join(out, "/")
}

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}
