package authprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// newAppleClientSecretMinter parses the developer .p8 key and returns a
// function that mints a fresh ES256 client secret JWT on each call.
// See https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
func newAppleClientSecretMinter(teamID, keyID, clientID string, privateKeyPEM []byte, ttl time.Duration) (func(context.Context) (string, error), error) {
	if teamID == "" || keyID == "" || clientID == "" || len(privateKeyPEM) == 0 {
		return nil, fmt.Errorf("%w: apple secret needs team id, key id, client id and private key", ErrProviderInvalid)
	}
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: apple private key is not PEM", ErrProviderInvalid)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if k2, err2 := x509.ParseECPrivateKey(block.Bytes); err2 == nil {
			keyAny = k2
		} else {
			return nil, fmt.Errorf("%w: apple private key: %v", ErrProviderInvalid, err)
		}
	}
	ecKey, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: apple private key is not ECDSA", ErrProviderInvalid)
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return func(context.Context) (string, error) {
		now := time.Now()
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": teamID,
			"iat": now.Unix(),
			"exp": now.Add(ttl).Unix(),
			"aud": "https://appleid.apple.com",
			"sub": clientID,
		})
		token.Header["kid"] = keyID
		signed, err := token.SignedString(ecKey)
		if err != nil {
			return "", errors.New("apple: sign client secret: " + err.Error())
		}
		return signed, nil
	}, nil
}
