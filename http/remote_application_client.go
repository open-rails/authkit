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

// OrgIssuersClient publishes THIS org's issuer registration to a resource
// server's inbound accept endpoint. It is the OUTBOUND (send-side) half of the
// AuthKit-owned federation handshake — the platform/IdP side (e.g. cozy-art)
// uses it to tell a resource server (e.g. tensorhub) "trust delegated tokens I
// mint with this issuer + JWKS URL". The resource server's
// handleOrgIssuerRegisterPOST stores the registration.
type OrgIssuersClient struct {
	httpClient *http.Client
	// AuthToken, when set, is sent as a Bearer token on the registration
	// request. The accept endpoint authorizes by org owner/admin, so this must
	// be a service token for a user who owns the org being registered.
	authToken string
}

// OrgIssuersClientOption configures a OrgIssuersClient.
type OrgIssuersClientOption func(*OrgIssuersClient)

// WithOrgIssuersHTTPClient sets the HTTP client used for registration calls.
func WithOrgIssuersHTTPClient(c *http.Client) OrgIssuersClientOption {
	return func(fc *OrgIssuersClient) {
		if c != nil {
			fc.httpClient = c
		}
	}
}

// WithOrgIssuersAuthToken sets the Bearer token used to authenticate to the
// resource server's accept endpoint (owner/admin of the org being registered).
func WithOrgIssuersAuthToken(token string) OrgIssuersClientOption {
	return func(fc *OrgIssuersClient) { fc.authToken = strings.TrimSpace(token) }
}

// NewOrgIssuersClient creates a OrgIssuersClient.
func NewOrgIssuersClient(opts ...OrgIssuersClientOption) *OrgIssuersClient {
	fc := &OrgIssuersClient{httpClient: defaultOutboundHTTPClient}
	for _, o := range opts {
		o(fc)
	}
	return fc
}

// OrgIssuersRegistration is the payload published to a resource server.
type OrgIssuersRegistration struct {
	// Slug is this remote_application's slug on the receiving service.
	Slug string
	// Issuer is THIS platform's issuer URL (the `iss` of delegated tokens).
	Issuer string
	// JWKSURI is where the resource server fetches THIS platform's public keys
	// (jwks mode — preferred). Mutually exclusive with PublicKeys.
	JWKSURI string
	// PublicKeys is the static-mode key list for platforms without a JWKS
	// endpoint (#74). Mutually exclusive with JWKSURI.
	PublicKeys []core.RemoteAppKey
	// AllowedOrigins is the exact browser Origin allow-list the resource server
	// should accept for delegated browser requests signed by this issuer.
	AllowedOrigins []string
}

// RegisterIssuer POSTs this remote_application's registration to the resource
// server's accept endpoint (acceptURL is the fully-qualified URL of the inbound
// handler, e.g. "https://tensorhub.example/api/v1/remote-applications"). It
// returns an error for non-2xx responses.
func (fc *OrgIssuersClient) RegisterIssuer(ctx context.Context, acceptURL string, reg OrgIssuersRegistration) error {
	acceptURL = strings.TrimSpace(acceptURL)
	if acceptURL == "" {
		return errors.New("accept URL required")
	}
	if strings.TrimSpace(reg.Slug) == "" || strings.TrimSpace(reg.Issuer) == "" {
		return errors.New("slug and issuer are required")
	}
	if _, err := core.NormalizeRemoteAppTrustSource(reg.JWKSURI, "", reg.PublicKeys); err != nil {
		return err
	}
	allowedOrigins, err := core.NormalizeAllowedOrigins(reg.AllowedOrigins)
	if err != nil {
		return err
	}

	payload := remoteApplicationRegistration{
		Slug:           strings.TrimSpace(reg.Slug),
		Issuer:         strings.TrimSpace(reg.Issuer),
		JWKSURI:        strings.TrimSpace(reg.JWKSURI),
		PublicKeys:     reg.PublicKeys,
		AllowedOrigins: allowedOrigins,
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
