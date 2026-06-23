package authbase

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrAttributeDefNotFound indicates no registered remote-application attribute
// definition matched.
var ErrAttributeDefNotFound = errors.New("attribute_def_not_found")

// ErrInvalidRemoteApplication indicates a malformed remote_application
// registration payload (including invalid allowed-origin values).
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
	PublicKeys     []RemoteAppKey
	Audiences      []string
	AllowedOrigins []string
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
