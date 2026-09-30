package iam

import (
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

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
// (stored as jsonb; edited like an authorized_keys file): exactly one of
// PublicKeyPEM and JWK. An empty KID takes the JWK's kid.
type RemoteApplicationKey struct {
	KID          string `json:"kid,omitempty" yaml:"kid,omitempty"`
	PublicKeyPEM string `json:"public_key_pem" yaml:"public_key_pem"`
	JWK          *JWK   `json:"jwk,omitempty" yaml:"jwk,omitempty"`
}

// RemoteApplication is a registered federation principal: an external issuer
// AuthKit trusts to mint delegated and remote-application tokens. Role and
// Permissions are read, never written: its role in its controlling group and
// the permissions that role confers now (none when it needs MFA, which an
// application cannot present).
type RemoteApplication struct {
	ID string `json:"id"`
	// GroupID is the controlling group. Registration takes it from the group
	// the application is registered in, never from this field.
	GroupID string `json:"group_id"`
	Issuer  string `json:"issuer"`   // OIDC iss
	JWKSURI string `json:"jwks_uri"` // OIDC jwks_uri (jwks mode only)
	// Mode is the trust source; empty infers static from PublicKeys, else jwks.
	Mode RemoteApplicationMode `json:"mode"`
	// PublicKeys is the static-mode key list (empty in jwks mode).
	PublicKeys []RemoteApplicationKey `json:"public_keys"`
	Enabled    bool                   `json:"enabled"`
	// TrustRoot is what may change the application's keys: the system
	// (manual) or a credentials manager of its controlling group (user).
	// Never the keypair alone.
	TrustRoot   ApplicationTrustRoot `json:"trust_root"`
	Role        Role                 `json:"role"`
	Permissions []Perm               `json:"permissions"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

// ApplicationTrustRoot is the authority that changes an application's keys.
type ApplicationTrustRoot string

const (
	ApplicationTrustRootManual ApplicationTrustRoot = "manual"
	ApplicationTrustRootUser   ApplicationTrustRoot = "user"
)

// AppRef addresses one remote application: by id or by issuer. Build it with
// AppByID or AppByIssuer; the zero AppRef finds nothing.
type AppRef struct {
	issuer bool
	value  string
}

func AppByID(id string) AppRef         { return AppRef{value: strings.TrimSpace(id)} }
func AppByIssuer(issuer string) AppRef { return AppRef{issuer: true, value: strings.TrimSpace(issuer)} }

// ID is the id of a by-id reference, "" otherwise.
func (r AppRef) ID() string {
	if r.issuer {
		return ""
	}
	return r.value
}

// Issuer is the issuer of a by-issuer reference, "" otherwise.
func (r AppRef) Issuer() string {
	if r.issuer {
		return r.value
	}
	return ""
}

func (r AppRef) IsZero() bool { return r.value == "" }

func (r AppRef) String() string {
	if r.issuer {
		return "issuer:" + r.value
	}
	return "id:" + r.value
}
