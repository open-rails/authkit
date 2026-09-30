package iam

// JWK is a JSON Web Key (RFC 7517): an RSA, EC or OKP public key.
// keys.PublicJWK builds one and keys.ParsePublicJWK reads it.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC / OKP
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}
