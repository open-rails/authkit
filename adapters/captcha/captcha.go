// Package captcha checks the bot challenge a browser solves before AuthKit
// texts or emails a code to an address it names: Cloudflare Turnstile or
// hCaptcha, through the provider's siteverify API. Wire New's Verifier as
// authkit.Deps.Captcha; auth-ui renders the widget GET /capabilities names.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
)

// Provider is a captcha service.
type Provider string

const (
	// Turnstile is Cloudflare Turnstile.
	Turnstile Provider = "turnstile"
	// HCaptcha is hCaptcha.
	HCaptcha Provider = "hcaptcha"
)

var verifyURLs = map[Provider]string{
	Turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	HCaptcha:  "https://api.hcaptcha.com/siteverify",
}

// Config configures New. Provider, SiteKey and Secret are required.
type Config struct {
	Provider Provider
	// SiteKey is the widget's public key; Secret its server-side secret.
	SiteKey string
	Secret  string
	// Hostnames, when set, are the only hostnames a token may be solved on
	// (siteverify's hostname): a token from a page elsewhere is refused.
	Hostnames []string
	// Client sends the siteverify requests (default: a 10s-timeout client).
	Client *http.Client
	// VerifyURL replaces the provider's siteverify endpoint (tests).
	VerifyURL string
}

// Verifier is an authkit.CaptchaVerifier.
type Verifier struct {
	provider  Provider
	siteKey   string
	secret    string
	hostnames []string
	client    *http.Client
	verifyURL string
}

// New validates cfg and returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	verifyURL, ok := verifyURLs[cfg.Provider]
	switch {
	case !ok:
		return nil, fmt.Errorf("captcha: unknown provider %q", cfg.Provider)
	case strings.TrimSpace(cfg.SiteKey) == "":
		return nil, errors.New("captcha: SiteKey is required")
	case strings.TrimSpace(cfg.Secret) == "":
		return nil, errors.New("captcha: Secret is required")
	}
	if cfg.VerifyURL != "" {
		verifyURL = cfg.VerifyURL
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	hostnames := make([]string, 0, len(cfg.Hostnames))
	for _, h := range cfg.Hostnames {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hostnames = append(hostnames, h)
		}
	}
	return &Verifier{provider: cfg.Provider, siteKey: strings.TrimSpace(cfg.SiteKey), secret: strings.TrimSpace(cfg.Secret),
		hostnames: hostnames, client: client, verifyURL: verifyURL}, nil
}

// Widget is the provider and site key the browser renders.
func (v *Verifier) Widget() iam.CaptchaWidget {
	return iam.CaptchaWidget{Provider: string(v.provider), SiteKey: v.siteKey}
}

// The provider's answer to a token. Both providers share these fields.
type siteverify struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
}

// refusals are the error codes that judge the token, not the request: any
// other means the provider could not tell (a wrong secret, an outage).
var refusals = []string{
	"missing-input-response", "invalid-input-response", "timeout-or-duplicate", // both
	"expired-input-response", "already-seen-response", "invalid-or-already-seen-response", // hCaptcha
}

// Verify asks the provider whether token was solved, once, at remoteIP: nil
// when it was, iam.ErrCaptchaFailed when the provider refused it, another
// error when it could not tell.
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) error {
	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	if v.provider == HCaptcha {
		form.Set("sitekey", v.siteKey)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: %s siteverify: %w", v.provider, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha: %s siteverify: HTTP %d", v.provider, res.StatusCode)
	}
	var out siteverify
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out); err != nil {
		return fmt.Errorf("captcha: %s siteverify: %w", v.provider, err)
	}
	if !out.Success {
		for _, code := range out.ErrorCodes {
			if !slices.Contains(refusals, code) {
				return fmt.Errorf("captcha: %s siteverify: %s", v.provider, strings.Join(out.ErrorCodes, ", "))
			}
		}
		return iam.ErrCaptchaFailed
	}
	if len(v.hostnames) > 0 && !slices.Contains(v.hostnames, strings.ToLower(out.Hostname)) {
		return iam.ErrCaptchaFailed
	}
	return nil
}
