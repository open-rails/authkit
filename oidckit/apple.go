package oidckit

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// AppleSecretConfig holds details needed to mint an Apple client_secret JWT.
// See: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
type AppleSecretConfig struct {
	TeamID        string        // Apple Developer Team ID (iss)
	KeyID         string        // Key ID (kid in header)
	ClientID      string        // Service ID / App ID (sub)
	PrivateKeyPEM []byte        // contents of the .p8 private key
	TTL           time.Duration // default 5 minutes if <= 0 (Apple allows up to 6 months)
}

// NewAppleClientSecretProvider returns a function that mints a fresh ES256 JWT for client_secret on each call.
func NewAppleClientSecretProvider(cfg AppleSecretConfig) (func(ctx context.Context) (string, error), error) {
	if cfg.TeamID == "" || cfg.KeyID == "" || cfg.ClientID == "" || len(cfg.PrivateKeyPEM) == 0 {
		return nil, errors.New("apple: missing required config")
	}
	block, _ := pem.Decode(cfg.PrivateKeyPEM)
	if block == nil {
		return nil, errors.New("apple: invalid private key pem")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Some keys might be in SEC1 EC format
		if k2, err2 := x509.ParseECPrivateKey(block.Bytes); err2 == nil {
			keyAny = k2
		} else {
			return nil, err
		}
	}
	ecKey, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple: private key is not ECDSA")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return func(ctx context.Context) (string, error) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": cfg.TeamID,
			"iat": now.Unix(),
			"exp": now.Add(ttl).Unix(),
			"aud": "https://appleid.apple.com",
			"sub": cfg.ClientID,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = cfg.KeyID
		return token.SignedString(ecKey)
	}, nil
}
