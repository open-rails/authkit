package authprovider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Kind string

const (
	KindOIDC   Kind = "oidc"
	KindOAuth2 Kind = "oauth2"

	// SecretStrategyAppleJWT selects dynamic Apple ES256 client-secret minting.
	SecretStrategyAppleJWT = "apple_jwt"
)

var ErrProviderNonHTTPSURL = errors.New("provider_non_https_url")

type Provider struct {
	Name            string
	Kind            Kind
	Issuer          string
	ClientID        string
	ClientSecret    ClientSecret
	Scopes          []string
	PKCE            bool
	AuthorizeURL    string
	TokenURL        string
	UserInfoURL     string
	UserInfoAccept  string
	ExtraAuthParams map[string]string

	// EmailFallbackURL is an optional secondary userinfo endpoint queried when the
	// primary userinfo response yields no email. It exists for OAuth2 providers
	// (GitHub) whose /user email may be empty; the fetched JSON is expected to be an
	// array of {email, primary, verified} entries, and the primary+verified entry is
	// selected. Empty for providers without a fallback.
	EmailFallbackURL    string
	EmailFallbackAccept string

	// IdentityMapper maps a provider's parsed userinfo JSON into an Identity. It is
	// required for OAuth2 providers (OIDC providers read standard ID-token claims via
	// the oidc path instead). Built-ins set this in-code; custom OAuth2 providers must
	// supply their own.
	IdentityMapper func(any) (Identity, error)

	// SecretProvider is the internal escape hatch for callers that already
	// construct dynamic secrets in code. Config-first providers should prefer
	// ClientSecret strategies.
	SecretProvider func(context.Context) (string, error)
}

// ClientSecret carries the provider's client secret as explicit config. There
// is deliberately NO env-var indirection (#231): AuthKit is a library and
// never reads process env — hosts/binaries resolve secrets at their own
// boundary and pass Value (or a Strategy) here.
type ClientSecret struct {
	Value    string
	Strategy string
	AppleJWT *AppleJWTSecret
}

type AppleJWTSecret struct {
	TeamID        string
	KeyID         string
	PrivateKeyPEM []byte
	TTL           time.Duration
}

type Identity struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	DisplayName       string
}

func BuiltIn(name string) (Provider, bool) {
	p, ok := builtIns[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Provider{}, false
	}
	return Clone(p), true
}

func Clone(in Provider) Provider {
	out := in
	out.Scopes = append([]string(nil), in.Scopes...)
	out.ExtraAuthParams = cloneStringMap(in.ExtraAuthParams)
	out.ClientSecret.AppleJWT = cloneAppleJWT(in.ClientSecret.AppleJWT)
	return out
}

func (p Provider) NormalizedName() string {
	return strings.ToLower(strings.TrimSpace(p.Name))
}

// ResolveStatic returns the statically configured secret value (empty when
// unset or when a dynamic Strategy is used instead).
func (s ClientSecret) ResolveStatic() string {
	return strings.TrimSpace(s.Value)
}

// Validate checks descriptor shape for config-loaded providers.
func (p Provider) Validate() error {
	if p.Kind == KindOAuth2 {
		if err := validateHTTPSURL(p.TokenURL); err != nil {
			return err
		}
		if err := validateHTTPSURL(p.UserInfoURL); err != nil {
			return err
		}
		if err := validateHTTPSURL(p.AuthorizeURL); err != nil {
			return err
		}
	}
	if err := validateHTTPSURL(p.EmailFallbackURL); err != nil {
		return err
	}
	return nil
}

func validateHTTPSURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrProviderNonHTTPSURL, raw)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %s", ErrProviderNonHTTPSURL, raw)
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAppleJWT(in *AppleJWTSecret) *AppleJWTSecret {
	if in == nil {
		return nil
	}
	out := *in
	out.PrivateKeyPEM = append([]byte(nil), in.PrivateKeyPEM...)
	return &out
}
