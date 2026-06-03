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
)

// FederationClient publishes THIS org's issuer registration to a resource
// server's inbound accept endpoint. It is the OUTBOUND (send-side) half of the
// AuthKit-owned federation handshake — the platform/IdP side (e.g. cozy-art)
// uses it to tell a resource server (e.g. tensorhub) "trust delegated tokens I
// mint with this issuer + JWKS URL". The resource server's
// handleFederatedIssuerRegisterPOST stores the registration.
type FederationClient struct {
	httpClient *http.Client
	// AuthToken, when set, is sent as a Bearer token on the registration
	// request. The accept endpoint authorizes by org owner/admin, so this must
	// be an access token for a user who owns the org being registered.
	authToken string
}

// FederationClientOption configures a FederationClient.
type FederationClientOption func(*FederationClient)

// WithFederationHTTPClient sets the HTTP client used for registration calls.
func WithFederationHTTPClient(c *http.Client) FederationClientOption {
	return func(fc *FederationClient) {
		if c != nil {
			fc.httpClient = c
		}
	}
}

// WithFederationAuthToken sets the Bearer token used to authenticate to the
// resource server's accept endpoint (owner/admin of the org being registered).
func WithFederationAuthToken(token string) FederationClientOption {
	return func(fc *FederationClient) { fc.authToken = strings.TrimSpace(token) }
}

// NewFederationClient creates a FederationClient.
func NewFederationClient(opts ...FederationClientOption) *FederationClient {
	fc := &FederationClient{httpClient: http.DefaultClient}
	for _, o := range opts {
		o(fc)
	}
	return fc
}

// FederationRegistration is the payload published to a resource server.
type FederationRegistration struct {
	// Org is this issuer's resource account slug on the receiving service.
	Org string
	// IssuerID is THIS platform's issuer URL (the `iss` of delegated tokens).
	IssuerID string
	// JWKSURL is where the resource server fetches THIS platform's public keys.
	JWKSURL string
}

// RegisterIssuer POSTs this org's issuer registration to the resource server's
// accept endpoint (acceptURL is the fully-qualified URL of the inbound
// handler, e.g. "https://tensorhub.example/api/v1/federated-issuers"). It
// returns an error for non-2xx responses.
func (fc *FederationClient) RegisterIssuer(ctx context.Context, acceptURL string, reg FederationRegistration) error {
	acceptURL = strings.TrimSpace(acceptURL)
	if acceptURL == "" {
		return errors.New("accept URL required")
	}
	if strings.TrimSpace(reg.Org) == "" || strings.TrimSpace(reg.IssuerID) == "" || strings.TrimSpace(reg.JWKSURL) == "" {
		return errors.New("org, issuer_id and jwks_url are required")
	}

	payload := federatedIssuerRegistration{
		Org:      strings.TrimSpace(reg.Org),
		IssuerID: strings.TrimSpace(reg.IssuerID),
		JWKSURL:  strings.TrimSpace(reg.JWKSURL),
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
