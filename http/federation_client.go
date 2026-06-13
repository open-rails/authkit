package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// TenantIssuersClient publishes THIS tenant's issuer registration to a resource
// server's inbound accept endpoint. It is the OUTBOUND (send-side) half of the
// AuthKit-owned federation handshake — the platform/IdP side (e.g. cozy-art)
// uses it to tell a resource server (e.g. tensorhub) "trust delegated tokens I
// mint with this issuer + JWKS URL". The resource server's
// handleTenantIssuerRegisterPOST stores the registration.
type TenantIssuersClient struct {
	httpClient *http.Client
	// AuthToken, when set, is sent as a Bearer token on the registration
	// request. The accept endpoint authorizes by tenant owner/admin, so this must
	// be a service token for a user who owns the tenant being registered.
	authToken string
}

// TenantIssuersClientOption configures a TenantIssuersClient.
type TenantIssuersClientOption func(*TenantIssuersClient)

// WithTenantIssuersHTTPClient sets the HTTP client used for registration calls.
func WithTenantIssuersHTTPClient(c *http.Client) TenantIssuersClientOption {
	return func(fc *TenantIssuersClient) {
		if c != nil {
			fc.httpClient = c
		}
	}
}

// WithTenantIssuersAuthToken sets the Bearer token used to authenticate to the
// resource server's accept endpoint (owner/admin of the tenant being registered).
func WithTenantIssuersAuthToken(token string) TenantIssuersClientOption {
	return func(fc *TenantIssuersClient) { fc.authToken = strings.TrimSpace(token) }
}

// NewTenantIssuersClient creates a TenantIssuersClient.
func NewTenantIssuersClient(opts ...TenantIssuersClientOption) *TenantIssuersClient {
	fc := &TenantIssuersClient{httpClient: defaultOutboundHTTPClient}
	for _, o := range opts {
		o(fc)
	}
	return fc
}

// TenantIssuersRegistration is the payload published to a resource server.
type TenantIssuersRegistration struct {
	// Tenant is this issuer's resource account slug on the receiving service.
	Tenant string
	// Issuer is THIS platform's issuer URL (the `iss` of delegated tokens).
	Issuer string
	// JWKSURI is where the resource server fetches THIS platform's public keys
	// (jwks mode — preferred). Mutually exclusive with PublicKeys.
	JWKSURI string
	// PublicKeys is the static-mode key list for platforms without a JWKS
	// endpoint (#465). Mutually exclusive with JWKSURI.
	PublicKeys []core.TenantIssuerKey
}

// RegisterIssuer POSTs this tenant's issuer registration to the resource server's
// accept endpoint (acceptURL is the fully-qualified URL of the inbound
// handler, e.g. "https://tensorhub.example/api/v1/tenant-issuers"). It
// returns an error for non-2xx responses.
func (fc *TenantIssuersClient) RegisterIssuer(ctx context.Context, acceptURL string, reg TenantIssuersRegistration) error {
	acceptURL = strings.TrimSpace(acceptURL)
	if acceptURL == "" {
		return errors.New("accept URL required")
	}
	if strings.TrimSpace(reg.Tenant) == "" || strings.TrimSpace(reg.Issuer) == "" {
		return errors.New("tenant and issuer are required")
	}
	if _, err := core.NormalizeTenantIssuerTrustSource(reg.JWKSURI, "", reg.PublicKeys); err != nil {
		return err
	}

	payload := tenantIssuerRegistration{
		Tenant:     strings.TrimSpace(reg.Tenant),
		Issuer:     strings.TrimSpace(reg.Issuer),
		JWKSURI:    strings.TrimSpace(reg.JWKSURI),
		PublicKeys: reg.PublicKeys,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, acceptURL, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if fc.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+fc.authToken)
	}

	resp, err := fc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("register issuer: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
