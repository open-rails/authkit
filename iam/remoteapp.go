package iam

import (
	"net/url"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// MaxRemoteApplicationIssuerLen bounds a remote-application issuer identifier.
// Registration refuses longer values and the verifier never consults the store
// for them (ak#297).
const MaxRemoteApplicationIssuerLen = 512

// ValidRemoteApplicationIssuer reports whether iss has the shape every
// registered remote-application issuer has: an absolute http(s) URL with a
// host, at most MaxRemoteApplicationIssuerLen bytes, no whitespace or control
// characters. Registration enforces it; the verifier applies the same rule to a
// token's self-asserted `iss` before any store lookup.
func ValidRemoteApplicationIssuer(iss string) bool {
	if iss == "" || len(iss) > MaxRemoteApplicationIssuerLen {
		return false
	}
	for _, r := range iss {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	u, err := url.Parse(iss)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// ErrInvalidRemoteApplication indicates a malformed remote_application
// registration payload.
var ErrInvalidRemoteApplication Error = errmodel.E(errmodel.CodeInvalidRemoteApplication)

// RemoteApplicationMode is a remote application's one trust source:
//
//	jwks   — keys fetched and refreshed from JWKSURI; rotation is publishing a
//	         new kid at the same URL.
//	static — a human-managed PEM list for principals without a JWKS endpoint.
type RemoteApplicationMode string

const (
	RemoteApplicationModeJWKS   RemoteApplicationMode = "jwks"
	RemoteApplicationModeStatic RemoteApplicationMode = "static"
)

// RemoteApplicationKey is one entry of a static-mode principal's human-managed key list
// (stored as jsonb; edited like an authorized_keys file).
type RemoteApplicationKey struct {
	KID          string `json:"kid,omitempty" yaml:"kid,omitempty"`
	PublicKeyPEM string `json:"public_key_pem" yaml:"public_key_pem"`
}

// RemoteApplicationAuthority is a remote application's stored authority: its
// effective permissions and the group they are bound to.
type RemoteApplicationAuthority struct {
	PermissionGroupID string
	AuthorityIssuer   string
	Permissions       []Perm
	Persona           Persona
}

// RemoteApplication is a registered federation principal: an external issuer
// AuthKit trusts to mint delegated and remote-application tokens.
type RemoteApplication struct {
	ID   string
	Slug string
	// PermissionGroupID is the controlling group. Registration takes it from
	// the group the application is registered in, never from this field.
	PermissionGroupID string
	Issuer            string // OIDC iss
	JWKSURI           string // OIDC jwks_uri (jwks mode only)
	// Mode is the trust source; empty infers static from PublicKeys, else jwks.
	Mode RemoteApplicationMode
	// PublicKeys is the static-mode key list (empty in jwks mode).
	PublicKeys []RemoteApplicationKey
	Enabled    bool
	// TrustRoot is what may change the application's keys: the system
	// (manual) or a credentials manager of its controlling group (user).
	// Never the keypair alone.
	TrustRoot ApplicationTrustRoot
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ApplicationTrustRoot is the authority that changes an application's keys.
type ApplicationTrustRoot string

const (
	ApplicationTrustRootManual ApplicationTrustRoot = "manual"
	ApplicationTrustRootUser   ApplicationTrustRoot = "user"
)
