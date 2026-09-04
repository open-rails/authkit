package authkit

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrAttributeDefNotFound indicates no registered remote-application attribute
// definition matched.
var ErrAttributeDefNotFound = errors.New("attribute_def_not_found")

// ErrInvalidRemoteApplication indicates a malformed remote_application
// registration payload.
var ErrInvalidRemoteApplication = errors.New("invalid_remote_application")

// Remote-application trust modes (#74). A remote_application is a federation
// PRINCIPAL whose credential is a key, with exactly one trust source:
//
//	jwks   — keys fetched + refreshed from JWKSURI; rotation is publishing a new
//	         kid at the same URL.
//	static — authorized_keys-style human-managed PEM list for principals without
//	         a JWKS endpoint; manual rotation by design.
const (
	RemoteAppModeJWKS   = "jwks"
	RemoteAppModeStatic = "static"
)

// RemoteAppKey is one entry of a static-mode principal's human-managed key list
// (stored as jsonb; edited like an authorized_keys file).
type RemoteAppKey struct {
	KID          string `json:"kid,omitempty" yaml:"kid,omitempty"`
	PublicKeyPEM string `json:"public_key_pem" yaml:"public_key_pem"`
}

// RemoteAppAttributeDef is a remote_application's registered attribute
// definition: the full inline value a REFERENCE-mode delegated-token attribute
// resolves to (#75). Definition is opaque JSON the consuming app interprets.
type RemoteAppAttributeDef struct {
	RemoteApplicationID string
	Key                 string
	Version             int32
	Definition          json.RawMessage
}

// RemoteApplicationAuthority is a remote_application's STORED authority: its
// role-resolved effective permissions plus the owning permission-group INSTANCE
// they are bound to (#248). InstanceSlug is "" for singleton personas (root).
// Exact-instance binding only; descendant/walk-down authority is deliberately
// deferred.
type RemoteApplicationAuthority struct {
	PermissionGroupID string
	AuthorityIssuer   string
	Permissions       []string
	Persona           string
	InstanceSlug      string
}

// RemoteApplication is a registered federation principal: an external issuer
// authkit trusts to mint delegated/remote-application tokens. It is a plain data
// view; persistence and lifecycle live in core.
type RemoteApplication struct {
	ID                string
	Slug              string
	PermissionGroupID string // controlling permission-group id
	Issuer            string // OIDC iss
	JWKSURI           string // OIDC jwks_uri (jwks mode only)
	// Mode is the trust source: RemoteAppModeJWKS (fetch from JWKSURI) XOR
	// RemoteAppModeStatic (human-managed PublicKeys list). Never both.
	Mode string
	// PublicKeys is the static-mode key list (empty in jwks mode).
	PublicKeys []RemoteAppKey
	Enabled    bool
	// DisplayName is free-form, non-unique vanity metadata (#264). The slug is
	// the public handle; the uuid is the internal join key.
	DisplayName string
	// Tier is the application's capability tier: ApplicationTierRegistered
	// (self-registered; zero default capability — authenticate + documents
	// only) or ApplicationTierApproved (an admin act on the host).
	Tier string
	// TrustRoot is what can rotate this application's keys (#264):
	// ApplicationTrustRootManual (admin/bootstrap-managed),
	// ApplicationTrustRootDomain (re-fetching Domain's application.json
	// re-proves control and adopts current keys), or
	// ApplicationTrustRootUser (the owning user's authenticated session).
	// Never the keypair alone.
	TrustRoot string
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

// Application capability tiers (#264).
const (
	ApplicationTierRegistered = "registered"
	ApplicationTierApproved   = "approved"
)

// Application trust roots (#264): the authority that rotates keys.
const (
	ApplicationTrustRootManual = "manual"
	ApplicationTrustRootDomain = "domain"
	ApplicationTrustRootUser   = "user"
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
	JWKSURI    string         `json:"jwks_uri,omitempty"`
	PublicKeys []RemoteAppKey `json:"public_keys,omitempty"`
	// DocumentEndpoint is the optional signed-document base URL.
	DocumentEndpoint string `json:"document_endpoint,omitempty"`
}

// RegisteredApplication is the result of a (re-)registration: the application
// row plus its service-owned org (the permission group the application
// principal owns).
type RegisteredApplication struct {
	Application     RemoteApplication
	OrgPersona      string
	OrgInstanceSlug string
	// Created is false for an idempotent re-registration (the boot-time
	// self-heal / rotation-from-root path).
	Created bool
}
