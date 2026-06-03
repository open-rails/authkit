package oidckit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/zitadel/oidc/v2/pkg/client/rp"
)

// DefaultRPCacheTTL is how long static-secret relying parties are cached after discovery.
const DefaultRPCacheTTL = time.Hour

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
	PKCE            bool
}

type rpCacheEntry struct {
	rp     rp.RelyingParty
	expiry time.Time
}

// Manager builds provider RPs and helps construct auth URLs with PKCE.
type Manager struct {
	providers map[string]RPClient
	cacheTTL  time.Duration

	mu      sync.RWMutex
	rpCache map[string]rpCacheEntry
}

// NewManager initializes the RP clients lazily on first use.
func NewManager(cfgs map[string]RPClient) *Manager {
	return &Manager{
		providers: cfgs,
		cacheTTL:  DefaultRPCacheTTL,
		rpCache:   make(map[string]rpCacheEntry),
	}
}

// Provider returns the configured RPClient for a provider slug (if present).
func (m *Manager) Provider(name string) (RPClient, bool) {
	pc, ok := m.providers[name]
	return pc, ok
}

// Begin returns an authorization URL for the given provider using PKCE and state/nonce you supply.
// The caller should persist state+verifier (e.g., Redis) and redirect the user to the returned URL.
func (m *Manager) Begin(ctx context.Context, provider, state, nonce, codeChallenge, redirectURI string) (string, error) {
	pc, ok := m.providers[provider]
	if !ok {
		return "", errors.New("unknown provider")
	}
	rpClient, err := m.rp(ctx, provider, pc, redirectURI)
	if err != nil {
		return "", err
	}

	// Build auth URL. PKCE S256 + nonce where supported.
	opts := []rp.AuthURLOpt{
		rp.AuthURLOpt(rp.WithURLParam("nonce", nonce)),
	}
	if pc.PKCE {
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

func (m *Manager) rpCacheKey(provider, redirectURI string) string {
	return provider + "|" + redirectURI
}

func (m *Manager) rp(ctx context.Context, provider string, pc RPClient, redirectURI string) (rp.RelyingParty, error) {
	// Dynamic client secrets (e.g. Apple ES256 JWT) must not be cached with a stale secret.
	if pc.ClientSecretProvider != nil {
		return m.buildRP(ctx, pc, redirectURI)
	}

	key := m.rpCacheKey(provider, redirectURI)
	now := time.Now()

	m.mu.RLock()
	if ent, ok := m.rpCache[key]; ok && now.Before(ent.expiry) {
		m.mu.RUnlock()
		return ent.rp, nil
	}
	m.mu.RUnlock()

	built, err := m.buildRP(ctx, pc, redirectURI)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.rpCache[key] = rpCacheEntry{rp: built, expiry: now.Add(m.cacheTTL)}
	m.mu.Unlock()
	return built, nil
}

func (m *Manager) buildRP(ctx context.Context, pc RPClient, redirectURI string) (rp.RelyingParty, error) {
	secret := pc.ClientSecret
	if pc.ClientSecretProvider != nil {
		s, err := pc.ClientSecretProvider(ctx)
		if err != nil {
			return nil, err
		}
		secret = s
	}
	return rp.NewRelyingPartyOIDC(
		pc.Issuer,
		pc.ClientID,
		secret,
		redirectURI,
		pc.Scopes,
		rp.WithHTTPClient(OutboundHTTPClient()),
	)
}

// GetRP exposes the relying party for a configured provider.
func (m *Manager) GetRPWithRedirect(ctx context.Context, provider, redirectURI string) (rp.RelyingParty, error) {
	pc, ok := m.providers[provider]
	if !ok {
		return nil, errors.New("unknown provider")
	}
	return m.rp(ctx, provider, pc, redirectURI)
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
	// Reauth* fields identify a step-up reauthentication flow for an existing
	// session. Login/link flows leave these empty.
	ReauthUserID    string
	ReauthSessionID string
	ReauthReturnTo  string
	UI              string // "popup" to trigger popup HTML callback; else redirect
	PopupNonce      string // echoed in popup postMessage for opener validation
}
