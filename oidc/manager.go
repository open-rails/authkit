package oidckit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/zitadel/oidc/v2/pkg/client/rp"
)

// RPClient holds issuer-based OIDC settings for a single IdP (internal RP wiring).
type RPClient struct {
	Issuer       string
	ClientID     string
	ClientSecret string // For Apple, supply a generated JWT client secret
	// ClientSecretProvider, if set, is called to obtain a fresh client_secret
	// whenever an RP is constructed (e.g., for Apple where the secret is a short‑lived ES256 JWT).
	ClientSecretProvider func(ctx context.Context) (string, error)
	Scopes               []string
	// Optional: additional auth params (e.g., response_mode)
	ExtraAuthParams map[string]string
}

// Manager builds provider RPs and helps construct auth URLs with PKCE.
type Manager struct{ providers map[string]RPClient }

// NewManager initializes the RP clients lazily on first use.
func NewManager(cfgs map[string]RPClient) *Manager { return &Manager{providers: cfgs} }

// Provider returns the configured RPClient for a provider slug (if present).
func (m *Manager) Provider(name string) (RPClient, bool) { pc, ok := m.providers[name]; return pc, ok }

// Begin returns an authorization URL for the given provider using PKCE and state/nonce you supply.
// The caller should persist state+verifier (e.g., Redis) and redirect the user to the returned URL.
func (m *Manager) Begin(ctx context.Context, provider, state, nonce, codeChallenge, redirectURI string) (string, error) {
	pc, ok := m.providers[provider]
	if !ok {
		return "", errors.New("unknown provider")
	}
	rpClient, err := m.rp(ctx, pc, redirectURI)
	if err != nil {
		return "", err
	}

	// Build auth URL. PKCE S256 + nonce where supported. Apple web flow may not accept PKCE.
	opts := []rp.AuthURLOpt{
		rp.AuthURLOpt(rp.WithURLParam("nonce", nonce)),
	}
	if provider != "apple" {
		opts = append(opts, rp.WithCodeChallenge(codeChallenge))
		opts = append(opts, rp.AuthURLOpt(rp.WithURLParam("code_challenge_method", "S256")))
	}
	if len(pc.ExtraAuthParams) > 0 {
		for k, v := range pc.ExtraAuthParams {
			opts = append(opts, rp.AuthURLOpt(rp.WithURLParam(k, v)))
		}
	}
	return rp.AuthURL(state, rpClient, opts...), nil
}

// getOrCreateRP initializes a relying party from discovery on first use.
func (m *Manager) rp(ctx context.Context, pc RPClient, redirectURI string) (rp.RelyingParty, error) {
	secret := pc.ClientSecret
	if pc.ClientSecretProvider != nil {
		if s, err := pc.ClientSecretProvider(ctx); err == nil {
			secret = s
		} else {
			return nil, err
		}
	}
	return rp.NewRelyingPartyOIDC(pc.Issuer, pc.ClientID, secret, redirectURI, pc.Scopes)
}

// GetRP exposes the relying party for a configured provider.
func (m *Manager) GetRPWithRedirect(ctx context.Context, provider, redirectURI string) (rp.RelyingParty, error) {
	pc, ok := m.providers[provider]
	if !ok {
		return nil, errors.New("unknown provider")
	}
	return m.rp(ctx, pc, redirectURI)
}

// IssuerFor returns the configured issuer URL for a provider slug.
func (m *Manager) IssuerFor(provider string) (string, bool) {
	pc, ok := m.providers[provider]
	if !ok {
		return "", false
	}
	return pc.Issuer, true
}

// GeneratePKCE returns a verifier and S256 challenge suitable for the auth request.
func GeneratePKCE() (verifier string, challenge string, err error) {
	v := make([]byte, 32)
	if _, err = rand.Read(v); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(v)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// StateCache stores ephemeral OIDC state/PKCE data (backed by Redis in the app).
type StateCache interface {
	Put(ctx context.Context, state string, data StateData) error
	Get(ctx context.Context, state string) (StateData, bool, error)
	Del(ctx context.Context, state string) error
}

// StateData is what we persist for a pending OIDC login.
type StateData struct {
	Provider    string
	Verifier    string
	Nonce       string
	RedirectURI string
	LinkUserID  string
	UI          string // "popup" to trigger popup HTML callback; else redirect
	PopupNonce  string // echoed in popup postMessage for opener validation
}
