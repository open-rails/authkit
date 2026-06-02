package authprovider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
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

var (
	ErrClientSecretEnvEmpty     = errors.New("client_secret_env_empty")
	ErrProviderInvalidTransform = errors.New("provider_invalid_transform")
	ErrProviderNonHTTPSURL      = errors.New("provider_non_https_url")
)

var allowedTransforms = map[string]struct{}{
	"":          {},
	"string":    {},
	"trim":      {},
	"lowercase": {},
}

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
	UserMapping     UserMapping
	EmailFallback   *FallbackLookup

	// IdentityMapper is an internal escape hatch for providers whose userinfo
	// response cannot be represented by declarative mappings.
	IdentityMapper func(any) (Identity, error)

	// SecretProvider is the internal escape hatch for callers that already
	// construct dynamic secrets in code. Config-first providers should prefer
	// ClientSecret strategies.
	SecretProvider func(context.Context) (string, error)
}

type ClientSecret struct {
	Value    string
	Env      string
	Strategy string
	AppleJWT *AppleJWTSecret
}

type AppleJWTSecret struct {
	TeamID        string
	KeyID         string
	PrivateKeyPEM []byte
	PrivateKeyEnv string
	TTL           time.Duration
}

type UserMapping struct {
	Subject           FieldMapping
	Email             FieldMapping
	EmailVerified     FieldMapping
	PreferredUsername FieldMapping
	DisplayName       FieldMapping
}

type FieldMapping struct {
	Path       string
	Value      any
	Transforms []string
}

type FallbackLookup struct {
	URL    string
	Accept string
	Array  bool
	Select map[string]any

	Email         FieldMapping
	EmailVerified FieldMapping
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

func BuiltIns() map[string]Provider {
	out := make(map[string]Provider, len(builtIns))
	for name, provider := range builtIns {
		out[name] = Clone(provider)
	}
	return out
}

func Clone(in Provider) Provider {
	out := in
	out.Scopes = append([]string(nil), in.Scopes...)
	out.ExtraAuthParams = cloneStringMap(in.ExtraAuthParams)
	out.UserMapping = cloneUserMapping(in.UserMapping)
	if in.EmailFallback != nil {
		cp := *in.EmailFallback
		cp.Select = cloneAnyMap(in.EmailFallback.Select)
		cp.Email.Transforms = append([]string(nil), in.EmailFallback.Email.Transforms...)
		cp.EmailVerified.Transforms = append([]string(nil), in.EmailFallback.EmailVerified.Transforms...)
		out.EmailFallback = &cp
	}
	out.ClientSecret.AppleJWT = cloneAppleJWT(in.ClientSecret.AppleJWT)
	return out
}

func (p Provider) NormalizedName() string {
	return strings.ToLower(strings.TrimSpace(p.Name))
}

func (s ClientSecret) ResolveStatic() (string, error) {
	if strings.TrimSpace(s.Value) != "" {
		return strings.TrimSpace(s.Value), nil
	}
	env := strings.TrimSpace(s.Env)
	if env != "" {
		v := strings.TrimSpace(os.Getenv(env))
		if v == "" {
			return "", fmt.Errorf("%w: %s", ErrClientSecretEnvEmpty, env)
		}
		return v, nil
	}
	if strings.TrimSpace(s.Strategy) != "" {
		return "", nil
	}
	return "", nil
}

// Validate checks descriptor shape for config-loaded providers.
func (p Provider) Validate() error {
	if err := validateUserMappingTransforms(p.UserMapping); err != nil {
		return err
	}
	if p.EmailFallback != nil {
		if err := validateFieldMappingTransforms(p.EmailFallback.Email); err != nil {
			return err
		}
		if err := validateFieldMappingTransforms(p.EmailFallback.EmailVerified); err != nil {
			return err
		}
		if err := validateHTTPSURL(p.EmailFallback.URL); err != nil {
			return err
		}
	}
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
	return nil
}

func MapIdentity(root any, mapping UserMapping) (Identity, error) {
	subject, err := mapString(root, mapping.Subject)
	if err != nil || strings.TrimSpace(subject) == "" {
		return Identity{}, errors.New("provider_mapping_missing_subject")
	}
	email, _ := mapString(root, mapping.Email)
	emailVerified, _ := mapBool(root, mapping.EmailVerified)
	preferred, _ := mapString(root, mapping.PreferredUsername)
	display, _ := mapString(root, mapping.DisplayName)
	return Identity{
		Subject:           strings.TrimSpace(subject),
		Email:             strings.TrimSpace(email),
		EmailVerified:     emailVerified,
		PreferredUsername: strings.TrimSpace(preferred),
		DisplayName:       strings.TrimSpace(display),
	}, nil
}

func MapFallbackEmail(root any, fallback FallbackLookup) (string, bool) {
	target := root
	if fallback.Array {
		items, ok := root.([]any)
		if !ok {
			return "", false
		}
		target = nil
		for _, item := range items {
			if matchesSelect(item, fallback.Select) {
				target = item
				break
			}
		}
		if target == nil {
			return "", false
		}
	}
	email, _ := mapString(target, fallback.Email)
	verified, _ := mapBool(target, fallback.EmailVerified)
	return strings.TrimSpace(email), verified
}

func mapString(root any, mapping FieldMapping) (string, error) {
	value, ok := mappedValue(root, mapping)
	if !ok || value == nil {
		return "", errors.New("missing_value")
	}
	out := fmt.Sprint(value)
	for _, transform := range mapping.Transforms {
		switch strings.ToLower(strings.TrimSpace(transform)) {
		case "", "string":
		case "trim":
			out = strings.TrimSpace(out)
		case "lowercase":
			out = strings.ToLower(out)
		}
	}
	return out, nil
}

func mapBool(root any, mapping FieldMapping) (bool, error) {
	value, ok := mappedValue(root, mapping)
	if !ok || value == nil {
		return false, errors.New("missing_value")
	}
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true"), nil
	case int:
		return v != 0, nil
	case int8:
		return v != 0, nil
	case int16:
		return v != 0, nil
	case int32:
		return v != 0, nil
	case int64:
		return v != 0, nil
	case uint:
		return v != 0, nil
	case uint8:
		return v != 0, nil
	case uint16:
		return v != 0, nil
	case uint32:
		return v != 0, nil
	case uint64:
		return v != 0, nil
	case float32:
		return v != 0, nil
	case float64:
		return v != 0, nil
	default:
		return false, nil
	}
}

func validateUserMappingTransforms(m UserMapping) error {
	for _, fm := range []FieldMapping{m.Subject, m.Email, m.EmailVerified, m.PreferredUsername, m.DisplayName} {
		if err := validateFieldMappingTransforms(fm); err != nil {
			return err
		}
	}
	return nil
}

func validateFieldMappingTransforms(m FieldMapping) error {
	for _, transform := range m.Transforms {
		if _, ok := allowedTransforms[strings.ToLower(strings.TrimSpace(transform))]; !ok {
			return fmt.Errorf("%w: %q", ErrProviderInvalidTransform, transform)
		}
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

func mappedValue(root any, mapping FieldMapping) (any, bool) {
	if mapping.Value != nil {
		return mapping.Value, true
	}
	if strings.TrimSpace(mapping.Path) == "" {
		return nil, false
	}
	return lookupPath(root, mapping.Path)
}

func lookupPath(root any, path string) (any, bool) {
	current := root
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func matchesSelect(root any, selectBy map[string]any) bool {
	if len(selectBy) == 0 {
		return true
	}
	for path, want := range selectBy {
		got, ok := lookupPath(root, path)
		if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
			return false
		}
	}
	return true
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

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneUserMapping(in UserMapping) UserMapping {
	out := in
	out.Subject.Transforms = append([]string(nil), in.Subject.Transforms...)
	out.Email.Transforms = append([]string(nil), in.Email.Transforms...)
	out.EmailVerified.Transforms = append([]string(nil), in.EmailVerified.Transforms...)
	out.PreferredUsername.Transforms = append([]string(nil), in.PreferredUsername.Transforms...)
	out.DisplayName.Transforms = append([]string(nil), in.DisplayName.Transforms...)
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
