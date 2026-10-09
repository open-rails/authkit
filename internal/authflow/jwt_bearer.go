package authflow

// RFC 7523 §2.1 JWT-bearer grant with a device-key capability (#437): a
// workload signs a short-lived assertion with its own P-256 key, carried in
// the header, proves the same key with DPoP, and embeds a capability one of
// the user's device keys signed offline (EdDSA) for that key: the operations
// it may do for the user on one resource until the capability expires.

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/jws"
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
	AssertionSkew = 30 * time.Second

	maxAssertionBytes = 16 << 10
)

// Reasons a jwt-bearer refusal carries (OAuthError.Reason).
const (
	ReasonAssertionInvalid   = "assertion_invalid"
	ReasonAssertionReplayed  = "assertion_replayed"
	ReasonCapabilityInvalid  = "capability_invalid"
	ReasonCapabilityExpired  = "capability_expired"
	ReasonCapabilityReplayed = "capability_replayed"
	ReasonDeviceKeyRevoked   = "device_key_revoked"
	ReasonKeyMismatch        = "key_mismatch"
	ReasonUserUnavailable    = "user_unavailable"
	ReasonRefused            = "refused"
)

// JWTBearerRefusal is invalid_grant with reason.
func JWTBearerRefusal(reason, description string) *OAuthError {
	return &OAuthError{Code: OAuthInvalidGrant, Description: description, Reason: reason}
}

// Assertion is a verified jwt-bearer assertion: the workload key that signed
// it (JKT), its claims, and the capability it carries, unverified.
type Assertion struct {
	JKT        string
	Subject    string
	ID         string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Claims     map[string]json.RawMessage
	Capability string
}

// Capability is a verified capability.
type Capability struct {
	UserID               string
	DeviceKeyID          string
	Audience             string
	JKT                  string
	AuthorizationDetails json.RawMessage
	ID                   string
	IssuedAt             time.Time
	ExpiresAt            time.Time
	Claims               map[string]json.RawMessage
}

var (
	assertionClaims  = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", devicekey.CapabilityClaim}
	capabilityClaims = []string{"sub", "aud", "exp", "nbf", "iat", "jti", "cnf", "authorization_details"}
)

// ParseJWTBearerAssertion verifies raw for clientID at tokenEndpoint: its
// ES256 signature by the P-256 key its header carries (typ, when present,
// "JWT"), iss the client, a sub, aud the token endpoint alone, exp no
// further than MaxAssertionLifetime ahead, a jti of 16-128 characters, and a
// capability. The jti's replay is the caller's to check.
func ParseJWTBearerAssertion(raw, clientID, tokenEndpoint string, now time.Time) (Assertion, *OAuthError) {
	invalid := func(description string) (Assertion, *OAuthError) {
		return Assertion{}, JWTBearerRefusal(ReasonAssertionInvalid, description)
	}
	if raw == "" {
		return Assertion{}, NewOAuthError(OAuthInvalidRequest, "assertion is required")
	}
	if len(raw) > maxAssertionBytes {
		return invalid("the assertion is too large")
	}
	parsed, err := jws.Parse(raw)
	if err != nil {
		return invalid("the assertion must be a JWT")
	}
	jkt, err := parsed.VerifyEmbeddedES256()
	if err != nil {
		return invalid("the assertion must be signed with ES256 by the P-256 key in its jwk header")
	}
	for name, value := range parsed.Header {
		switch {
		case name == "alg", name == "jwk":
		case name == "typ" && strings.EqualFold(jws.String(value), "JWT"):
		default:
			return invalid("the assertion header may carry only alg, jwk and typ JWT")
		}
	}
	c := parsed.Claims
	a := Assertion{JKT: jkt, Subject: jws.String(c["sub"]), ID: jws.String(c["jti"]), Capability: jws.String(c[devicekey.CapabilityClaim])}
	switch {
	case jws.String(c["iss"]) != clientID:
		return invalid("the assertion's iss must be the client_id")
	case !printable(a.Subject, 256):
		return invalid("the assertion needs a sub naming the workload")
	case !soleAudience(c["aud"], tokenEndpoint):
		return invalid("the assertion's aud must be the token endpoint, alone")
	case len(a.ID) < 16 || !printable(a.ID, 128):
		return invalid("the assertion needs a jti of 16 to 128 characters")
	case a.Capability == "":
		return invalid("the assertion must carry a capability")
	}
	var why string
	if a.IssuedAt, a.ExpiresAt, why = lifetime(c, now, MaxAssertionLifetime); why != "" {
		return invalid("the assertion " + why)
	}
	a.Claims = others(c, assertionClaims)
	return a, nil
}

// CapabilityKeyID is the device key id a capability names (kid), before
// its signature is checked.
func CapabilityKeyID(raw string) (string, *OAuthError) {
	parsed, err := jws.Parse(raw)
	kid := ""
	if err == nil {
		kid = jws.String(parsed.Header["kid"])
	}
	if !isUUID(kid) {
		return "", JWTBearerRefusal(ReasonCapabilityInvalid, "the capability must be a JWT whose kid is a device key id")
	}
	return strings.ToLower(kid), nil
}

// VerifyCapability verifies raw's EdDSA signature by key, the device key
// kid, and its claims at now: typ devicekey.CapabilityType, a user sub, a sole aud,
// cnf.jkt alone, a jti of 16-128 characters, authorization_details, and exp
// no further than MaxCapabilityLifetime ahead. Whose key it is, the binding,
// the operations' types and the replay are the caller's to check.
func VerifyCapability(raw, kid string, key ed25519.PublicKey, now time.Time) (Capability, *OAuthError) {
	invalid := func(description string) (Capability, *OAuthError) {
		return Capability{}, JWTBearerRefusal(ReasonCapabilityInvalid, description)
	}
	parsed, err := jws.Parse(raw)
	if err != nil {
		return invalid("the capability must be a JWT")
	}
	if len(parsed.Header) != 3 || !strings.EqualFold(jws.String(parsed.Header["kid"]), kid) || jws.String(parsed.Header["typ"]) != devicekey.CapabilityType {
		return invalid("the capability header must be exactly alg EdDSA, typ " + devicekey.CapabilityType + " and kid")
	}
	if parsed.VerifyEdDSA(key) != nil {
		return invalid("the capability's signature is not its device key's")
	}
	c := parsed.Claims
	out := Capability{
		UserID: strings.ToLower(jws.String(c["sub"])), DeviceKeyID: kid, ID: jws.String(c["jti"]),
		AuthorizationDetails: append(json.RawMessage(nil), c["authorization_details"]...),
	}
	var aud []string
	if json.Unmarshal(c["aud"], &aud) != nil {
		aud = []string{jws.String(c["aud"])}
	}
	cnf, _ := jws.Object(c["cnf"])
	switch {
	case !isUUID(out.UserID):
		return invalid("the capability's sub must be a user id")
	case len(aud) != 1 || aud[0] == "":
		return invalid("the capability needs one aud, the resource")
	case len(cnf) != 1 || !jose.ValidThumbprint(jws.String(cnf[jose.JWKThumbprintMember])):
		return invalid("the capability's cnf must be the workload key's jkt alone")
	case len(out.ID) < 16 || !printable(out.ID, 128):
		return invalid("the capability needs a jti of 16 to 128 characters")
	case len(out.AuthorizationDetails) == 0:
		return invalid("the capability needs authorization_details")
	}
	out.Audience, out.JKT = aud[0], jws.String(cnf[jose.JWKThumbprintMember])
	var why string
	if out.IssuedAt, out.ExpiresAt, why = lifetime(c, now, devicekey.MaxCapabilityLifetime); why != "" {
		if why == whyExpired {
			return Capability{}, JWTBearerRefusal(ReasonCapabilityExpired, "the capability has expired")
		}
		return invalid("the capability " + why)
	}
	out.Claims = others(c, capabilityClaims)
	return out, nil
}

const whyExpired = "has expired"

// lifetime checks exp (required, at most max ahead), nbf and iat (optional,
// not in the future) at now, with AssertionSkew; why says what is wrong.
func lifetime(c map[string]json.RawMessage, now time.Time, max time.Duration) (iat, exp time.Time, why string) {
	exp, ok := numericDate(c["exp"], true)
	switch {
	case !ok:
		return iat, exp, "needs an exp"
	case !now.Before(exp.Add(AssertionSkew)):
		return iat, exp, whyExpired
	case exp.After(now.Add(max + AssertionSkew)):
		return iat, exp, "expires too far ahead"
	}
	for _, name := range []string{"nbf", "iat"} {
		at, ok := numericDate(c[name], false)
		switch {
		case !ok:
			return iat, exp, "has a malformed " + name
		case at.After(now.Add(AssertionSkew)):
			return iat, exp, "has " + name + " in the future"
		case name == "iat":
			iat = at
		}
	}
	return iat, exp, ""
}

// soleAudience is whether aud names only want: a string, or an array
// holding just it.
func soleAudience(aud json.RawMessage, want string) bool {
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

// others is c without the claims AuthKit defines; nil when nothing is left.
func others(c map[string]json.RawMessage, defined []string) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	for name, value := range c {
		if slices.Contains(defined, name) {
			continue
		}
		if out == nil {
			out = map[string]json.RawMessage{}
		}
		out[name] = append(json.RawMessage(nil), value...)
	}
	return out
}

// printable is a non-empty printable string of at most max bytes without
// spaces.
func printable(s string, max int) bool {
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

func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil && len(s) == 36
}
