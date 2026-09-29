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
	Permissions       []string
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
	// DisplayName is free-form, non-unique vanity metadata (#264). The slug is
	// the public handle; the uuid is the internal join key.
	DisplayName string
	// Tier is the application's capability tier. Only the system approves;
	// every group or domain registration starts at ApplicationTierRegistered.
	Tier ApplicationTier
	// TrustRoot is what may rotate the application's keys: the system
	// (manual), a fresh proof of Domain (domain), or a credentials manager of
	// its controlling group (user). Never the keypair alone.
	TrustRoot ApplicationTrustRoot
	// Domain is the trust-root location for domain-rooted applications (the
	// canonical registration input; empty otherwise). Domains and slugs are
	// SEPARATE: the domain proves identity, the slug is a claimed handle.
	Domain string
	// DocumentEndpoint is the application's optional signed-document base URL
	// declared in its application.json.
	DocumentEndpoint string
	// RootVerifiedAt is the last successful trust-root proof (zero when the
	// root was never proven, e.g. manual registrations).
	RootVerifiedAt time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ApplicationTier is a remote application's capability tier.
type ApplicationTier string

const (
	ApplicationTierRegistered ApplicationTier = "registered"
	ApplicationTierApproved   ApplicationTier = "approved"
)

// ApplicationTrustRoot is the authority that rotates an application's keys.
type ApplicationTrustRoot string

const (
	ApplicationTrustRootManual ApplicationTrustRoot = "manual"
	ApplicationTrustRootDomain ApplicationTrustRoot = "domain"
	ApplicationTrustRootUser   ApplicationTrustRoot = "user"
)

// ApplicationWellKnownPath is where a domain-registered application serves its
// ApplicationDocument. Fetching it over HTTPS IS the domain-control proof.
const ApplicationWellKnownPath = "/.well-known/authkit/application.json"

// ApplicationDocument is the well-known application.json a self-registering
// application serves at https://<domain>/.well-known/authkit/application.json.
// Unknown fields are ignored (forward-compatible).
type ApplicationDocument struct {
	// Slug is the REQUESTED handle — a free claim through the same
	// availability + anti-squat gates as any org (slugs and domains are
	// separate). Empty defaults to the serving domain's hostname.
	Slug string `json:"slug"`
	// DisplayName is free-form, non-unique metadata.
	DisplayName string `json:"display_name,omitempty"`
	// Issuer is the application's token `iss`; its host must be the serving
	// domain outside dev-like environments.
	Issuer string `json:"issuer"`
	// JWKSURI XOR PublicKeys: exactly one trust source.
	JWKSURI    string                 `json:"jwks_uri,omitempty"`
	PublicKeys []RemoteApplicationKey `json:"public_keys,omitempty"`
	// DocumentEndpoint is the optional signed-document base URL.
	DocumentEndpoint string `json:"document_endpoint,omitempty"`
}

// RemoteApplicationAccess is a remote-application access token to mint: the
// application acting as itself. Identity is the issuer and authority is what
// the verifying deployment stores for it.
type RemoteApplicationAccess struct {
	// Issuer becomes iss: the application's registered issuer. Empty means
	// this deployment's issuer.
	Issuer    string
	Audiences []string
	// TTL defaults to 15m.
	TTL       time.Duration
	JTI       string
	NotBefore time.Time
	// Permissions, when non-nil, narrows the stored authority (an empty slice
	// narrows it to nothing); a permission outside it fails verification.
	Permissions []string
}
