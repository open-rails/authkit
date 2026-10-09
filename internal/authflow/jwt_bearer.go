package authflow

// RFC 7523 §2.1 JWT-bearer assertions (#437): a workload signs a short-lived
// assertion with its own P-256 key, carried in the header, and proves the
// same key with DPoP. AuthKit holds nothing per workload: the host's grant
// authorizer recognizes the key.

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/dpop"
)

// OAuthJWTBearer is a jwt-bearer token request: Assertion, and JKT, the key
// the request's DPoP proof proved ("" without one).
type OAuthJWTBearer struct {
	ClientID  string
	Assertion string
	Resource  string
	Scopes    []string
	JKT       string
}

const (
	// MaxAssertionLifetime bounds an assertion's exp from now.
	MaxAssertionLifetime = 5 * time.Minute
	// AssertionSkew is the clock skew allowed on exp, nbf and iat.
	AssertionSkew     = 30 * time.Second
	maxAssertionBytes = 16 << 10
)

// registeredAssertionClaims are the claims AuthKit checks itself; every
// other claim reaches the host as OAuthAssertion.Claims.
var registeredAssertionClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

// ParseJWTBearerAssertion verifies raw for clientID at tokenEndpoint: its
// ES256 signature by the P-256 key its header carries (typ, when present,
// "JWT"), iss the client, aud the token endpoint alone, exp no further than
// MaxAssertionLifetime ahead, and a jti of 16-128 characters. It returns the
// key's thumbprint; the jti's replay is the caller's to check.
func ParseJWTBearerAssertion(raw, clientID, tokenEndpoint string, now time.Time) (string, iam.OAuthAssertion, *OAuthError) {
	invalid := func(description string) (string, iam.OAuthAssertion, *OAuthError) {
		return "", iam.OAuthAssertion{}, NewOAuthError(OAuthInvalidGrant, description)
	}
	if raw == "" {
		return "", iam.OAuthAssertion{}, NewOAuthError(OAuthInvalidRequest, "assertion is required")
	}
	if len(raw) > maxAssertionBytes {
		return invalid("the assertion is too large")
	}
	header, claims, thumbprint, err := dpop.ParseKeyJWS(raw)
	if err != nil {
		return invalid("the assertion must be an ES256 JWT signed by the P-256 key in its jwk header")
	}
	for name, value := range header {
		switch {
		case name == "alg", name == "jwk":
		case name == "typ" && strings.EqualFold(stringClaim(value), "JWT"):
		default:
			return invalid("the assertion header may carry only alg, jwk and typ JWT")
		}
	}
	a := iam.OAuthAssertion{Subject: stringClaim(claims["sub"]), ID: stringClaim(claims["jti"])}
	switch {
	case stringClaim(claims["iss"]) != clientID:
		return invalid("the assertion's iss must be the client_id")
	case !validAssertionName(a.Subject, 256):
		return invalid("the assertion needs a sub naming the workload")
	case !assertionAudience(claims["aud"], tokenEndpoint):
		return invalid("the assertion's aud must be the token endpoint, alone")
	case len(a.ID) < 16 || !validAssertionName(a.ID, 128):
		return invalid("the assertion needs a jti of 16 to 128 characters")
	}
	exp, ok := numericDate(claims["exp"], true)
	switch {
	case !ok:
		return invalid("the assertion needs an exp")
	case !now.Before(exp.Add(AssertionSkew)):
		return invalid("the assertion has expired")
	case exp.After(now.Add(MaxAssertionLifetime + AssertionSkew)):
		return invalid("the assertion's exp is more than 5 minutes ahead")
	}
	a.ExpiresAt = exp
	for _, name := range []string{"nbf", "iat"} {
		at, ok := numericDate(claims[name], false)
		switch {
		case !ok:
			return invalid("the assertion's " + name + " must be a NumericDate")
		case at.After(now.Add(AssertionSkew)):
			return invalid("the assertion's " + name + " is in the future")
		case name == "iat":
			a.IssuedAt = at
		}
	}
	for name, value := range claims {
		if !slices.Contains(registeredAssertionClaims, name) {
			if a.Claims == nil {
				a.Claims = map[string]json.RawMessage{}
			}
			a.Claims[name] = append(json.RawMessage(nil), value...)
		}
	}
	return thumbprint, a, nil
}

// assertionAudience is whether aud names only want: a string, or an array
// holding just it.
func assertionAudience(aud json.RawMessage, want string) bool {
	if want == "" {
		return false
	}
	var one string
	if json.Unmarshal(aud, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(aud, &many) == nil && len(many) == 1 && many[0] == want
}

// numericDate reads an integer NumericDate; an absent optional one is the
// zero time.
func numericDate(raw json.RawMessage, required bool) (time.Time, bool) {
	if raw == nil {
		return time.Time{}, !required
	}
	var n int64
	if json.Unmarshal(raw, &n) != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// validAssertionName is a non-empty printable string of at most max bytes
// without spaces.
func validAssertionName(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func stringClaim(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}
