package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"io"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

// RemoteApplicationIssuersClient publishes this remote application's issuer
// registration to a resource server's inbound accept endpoint. It is the
// outbound half of the AuthKit-owned federation handshake: the platform/IdP
// side tells a resource server "trust delegated tokens I mint with this issuer
// + JWKS URL".
type RemoteApplicationIssuersClient struct {
	httpClient *http.Client
	// AuthToken, when set, is sent as a Bearer token on the registration
	// request. The accept endpoint authorizes through the receiving
	// permission-group route.
	authToken string
	// allowInsecureJWKS relaxes the pre-flight jwks_uri check for dev
	// federation; the receiving server enforces its own environment policy.
	allowInsecureJWKS bool
}

// RemoteApplicationIssuersClientOption configures a RemoteApplicationIssuersClient.
type RemoteApplicationIssuersClientOption func(*RemoteApplicationIssuersClient)

// WithRemoteApplicationIssuersHTTPClient sets the HTTP client used for
// registration calls.
func WithRemoteApplicationIssuersHTTPClient(c *http.Client) RemoteApplicationIssuersClientOption {
	return func(fc *RemoteApplicationIssuersClient) {
		if c != nil {
			fc.httpClient = c
		}
	}
}

// WithRemoteApplicationIssuersAuthToken sets the Bearer token used to
// authenticate to the resource server's accept endpoint.
func WithRemoteApplicationIssuersAuthToken(token string) RemoteApplicationIssuersClientOption {
	return func(fc *RemoteApplicationIssuersClient) { fc.authToken = strings.TrimSpace(token) }
}

// WithRemoteApplicationIssuersInsecureJWKS permits non-HTTPS/private jwks_uri
// values in the pre-flight check (#257, dev federation only); the receiving
// server still enforces its own environment policy.
func WithRemoteApplicationIssuersInsecureJWKS() RemoteApplicationIssuersClientOption {
	return func(fc *RemoteApplicationIssuersClient) { fc.allowInsecureJWKS = true }
}

// NewRemoteApplicationIssuersClient creates a RemoteApplicationIssuersClient.
func NewRemoteApplicationIssuersClient(opts ...RemoteApplicationIssuersClientOption) *RemoteApplicationIssuersClient {
	fc := &RemoteApplicationIssuersClient{httpClient: defaultOutboundHTTPClient}
	for _, o := range opts {
		o(fc)
	}
	return fc
}

// RemoteApplicationIssuerRegistration is the payload published to a resource server.
type RemoteApplicationIssuerRegistration struct {
	// Slug is this remote_application's slug on the receiving service.
	Slug string
	// Issuer is THIS platform's issuer URL (the `iss` of delegated tokens).
	Issuer string
	// JWKSURI is where the resource server fetches THIS platform's public keys
	// (jwks mode — preferred). Mutually exclusive with PublicKeys.
	JWKSURI string
	// PublicKeys is the static-mode key list for platforms without a JWKS
	// endpoint (#74). Mutually exclusive with JWKSURI.
	PublicKeys []authkit.RemoteAppKey
}

// RegisterIssuer POSTs this remote_application's registration to the resource
// server's accept endpoint (acceptURL is the fully-qualified URL of the inbound
// handler, e.g. "https://tensorhub.example/api/v1/remote-applications"). It
// returns an error for non-2xx responses.
func (fc *RemoteApplicationIssuersClient) RegisterIssuer(ctx context.Context, acceptURL string, reg RemoteApplicationIssuerRegistration) error {
	acceptURL = strings.TrimSpace(acceptURL)
	if acceptURL == "" {
		return errors.New("accept URL required")
	}
	if strings.TrimSpace(reg.Slug) == "" || strings.TrimSpace(reg.Issuer) == "" {
		return errors.New("slug and issuer are required")
	}
	if _, err := embedded.NormalizeRemoteAppTrustSource(reg.JWKSURI, "", reg.PublicKeys, fc.allowInsecureJWKS); err != nil {
		return err
	}

	payload := remoteApplicationRegistration{
		Slug:       strings.TrimSpace(reg.Slug),
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

// remoteApplicationRegistration is the JSON payload RegisterIssuer posts to a
// remote AuthKit's remote-application registration endpoint (#111: the issuer is
// nested under a permission-group on the receiving side).
type remoteApplicationRegistration struct {
	Slug       string                 `json:"slug"`
	Issuer     string                 `json:"issuer"`
	JWKSURI    string                 `json:"jwks_uri,omitempty"`
	PublicKeys []authkit.RemoteAppKey `json:"public_keys,omitempty"`
}
