package devicekey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Capabilities: a device key signs, offline, what a workload may do for its
// user. The workload embeds the capability in its jwt-bearer assertion
// (claim CapabilityClaim) and gets an access token for Audience that
// carries exactly those operations until the capability expires. AuthKit
// verifies the signature, that the key is live and the user's, and that the
// workload proves the key the capability names.
const (
	// CapabilityType is a capability's JOSE typ.
	CapabilityType = "authkit-capability+jwt"
	// CapabilityClaim is the jwt-bearer assertion claim that carries one.
	CapabilityClaim = "capability"
	// MaxCapabilityLifetime bounds a capability's ExpiresAt from now.
	MaxCapabilityLifetime = 24 * time.Hour
)

// Capability is what a device key lets a workload do for its user.
type Capability struct {
	// UserID (sub) is the device key's user.
	UserID string
	// Audience (aud) is the resource server's identifier, as the
	// authorization server declares it.
	Audience string
	// WorkloadThumbprint (cnf.jkt) is the RFC 7638 thumbprint of the
	// workload's P-256 key, the key its assertion and DPoP proofs use.
	WorkloadThumbprint string
	// AuthorizationDetails are the operations: an RFC 9396 JSON array whose
	// types the client declares.
	AuthorizationDetails json.RawMessage
	// ID (jti) redeems once; "" makes a random one.
	ID string
	// IssuedAt (iat) is zero for now.
	IssuedAt time.Time
	// ExpiresAt (exp) is required, at most MaxCapabilityLifetime ahead.
	ExpiresAt time.Time
	// Claims are other claims, such as the host's run id.
	Claims map[string]any
}

// SignCapability signs c with the Ed25519 key enrolled as deviceKeyID and
// returns the compact JWT.
func SignCapability(key crypto.Signer, deviceKeyID string, c Capability) (string, error) {
	if !isEd25519(key) {
		return "", errors.New("devicekey: the key is not an Ed25519 signer")
	}
	switch {
	case deviceKeyID == "":
		return "", errors.New("devicekey: capability: the device key id is required")
	case c.UserID == "" || c.Audience == "" || c.WorkloadThumbprint == "":
		return "", errors.New("devicekey: capability: UserID, Audience and WorkloadThumbprint are required")
	case !json.Valid(c.AuthorizationDetails) || len(c.AuthorizationDetails) == 0 || c.AuthorizationDetails[0] != '[':
		return "", errors.New("devicekey: capability: AuthorizationDetails must be a JSON array")
	case c.ExpiresAt.IsZero():
		return "", errors.New("devicekey: capability: ExpiresAt is required")
	}
	if c.ID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		c.ID = base64.RawURLEncoding.EncodeToString(b)
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now()
	}
	claims := map[string]any{}
	for name, value := range c.Claims {
		claims[name] = value
	}
	for name, value := range map[string]any{
		"sub": c.UserID, "aud": c.Audience, "cnf": map[string]string{"jkt": c.WorkloadThumbprint},
		"authorization_details": c.AuthorizationDetails, "jti": c.ID, "iat": c.IssuedAt.Unix(), "exp": c.ExpiresAt.Unix(),
	} {
		if _, taken := claims[name]; taken {
			return "", fmt.Errorf("devicekey: capability: Claims may not set %q", name)
		}
		claims[name] = value
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": CapabilityType, "kid": deviceKeyID})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("devicekey: capability: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := key.Sign(nil, []byte(input), crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("devicekey: sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return "", errors.New("devicekey: the signer returned no Ed25519 signature")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
