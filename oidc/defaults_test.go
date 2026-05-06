package oidckit

import "testing"

func TestNewManagerFromMinimalDoesNotForceOpenIDForDiscord(t *testing.T) {
	m := NewManagerFromMinimal(map[string]RPConfig{
		"discord": {ClientID: "discord-client"},
	})
	rp, ok := m.Provider("discord")
	if !ok {
		t.Fatalf("expected discord provider")
	}
	for _, scope := range rp.Scopes {
		if scope == "openid" {
			t.Fatalf("discord is OAuth2, not OIDC; scopes must not force openid: %v", rp.Scopes)
		}
	}
}

func TestNewManagerFromMinimalKeepsOpenIDForOIDCProviders(t *testing.T) {
	m := NewManagerFromMinimal(map[string]RPConfig{
		"google": {ClientID: "google-client", Scopes: []string{"email"}},
	})
	rp, ok := m.Provider("google")
	if !ok {
		t.Fatalf("expected google provider")
	}
	for _, scope := range rp.Scopes {
		if scope == "openid" {
			return
		}
	}
	t.Fatalf("google is OIDC; scopes must include openid: %v", rp.Scopes)
}
