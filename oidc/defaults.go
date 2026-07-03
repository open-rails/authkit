package oidckit

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/authprovider"
)

// RPConfig describes an IdP (Relying Party) with minimal fields.
// If ClientSecret is empty and SecretProvider is set, the manager will call it
// to obtain a short‑lived client_secret (e.g., Apple’s ES256 JWT).
type RPConfig struct {
	ClientID     string
	ClientSecret string
	// Optional: dynamic secret minting
	SecretProvider func(ctx context.Context) (string, error)
	// Optional: additional/override scopes. "openid" will be ensured.
	Scopes []string
}

func NewManagerFromProviders(providers map[string]authprovider.Provider) *Manager {
	cfgs := make(map[string]RPClient, len(providers))
	for name, provider := range providers {
		client, err := RPClientFromProvider(provider)
		if err != nil {
			continue
		}
		cfgs[name] = client
	}
	return NewManager(cfgs)
}

func RPClientFromProvider(provider authprovider.Provider) (RPClient, error) {
	secret := provider.ClientSecret.ResolveStatic()
	client := RPClient{
		Issuer:               strings.TrimSpace(provider.Issuer),
		ClientID:             strings.TrimSpace(provider.ClientID),
		ClientSecret:         secret,
		ClientSecretProvider: provider.SecretProvider,
		Scopes:               append([]string(nil), provider.Scopes...),
		ExtraAuthParams:      cloneStringMap(provider.ExtraAuthParams),
		PKCE:                 provider.PKCE,
	}
	if len(client.Scopes) == 0 {
		client.Scopes = []string{"openid", "email", "profile"}
	}
	if provider.Kind == authprovider.KindOIDC {
		client.Scopes = ensureOpenID(client.Scopes)
	}
	if strings.EqualFold(strings.TrimSpace(provider.ClientSecret.Strategy), authprovider.SecretStrategyAppleJWT) {
		sp, err := appleJWTSecretProvider(provider)
		if err != nil {
			return RPClient{}, err
		}
		client.ClientSecretProvider = sp
	}
	return client, nil
}

func appleJWTSecretProvider(provider authprovider.Provider) (func(context.Context) (string, error), error) {
	spec := provider.ClientSecret.AppleJWT
	if spec == nil {
		spec = &authprovider.AppleJWTSecret{}
	}
	// Explicit PEM only — no env-var indirection (#231): hosts resolve the key
	// at their own boundary and pass AppleJWTSecret.PrivateKeyPEM.
	privateKey := append([]byte(nil), spec.PrivateKeyPEM...)
	return NewAppleClientSecretProvider(AppleSecretConfig{
		TeamID:        spec.TeamID,
		KeyID:         spec.KeyID,
		ClientID:      provider.ClientID,
		PrivateKeyPEM: privateKey,
		TTL:           spec.TTL,
	})
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

func ensureOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append(scopes, "openid")
}
