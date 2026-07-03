package authhttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/authprovider"
)

type oauth2TokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
}

type oauth2UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Preferred     string
	Display       string
}

func (s *Service) oauth2Provider(provider string) (authprovider.Provider, bool) {
	cfg, ok := s.authProvider(provider)
	if !ok || cfg.Kind != authprovider.KindOAuth2 {
		return authprovider.Provider{}, false
	}
	return cfg, true
}

func (s *Service) fetchOAuthUserInfo(r *http.Request, cfg authprovider.Provider, token oauth2TokenResp) (oauth2UserInfo, error) {
	var root any
	if err := oauth2GetJSON(r, cfg.UserInfoURL, token, cfg.UserInfoAccept, &root); err != nil {
		return oauth2UserInfo{}, err
	}
	if cfg.IdentityMapper == nil {
		return oauth2UserInfo{}, errors.New("userinfo_failed")
	}
	identity, err := cfg.IdentityMapper(root)
	if err != nil {
		return oauth2UserInfo{}, errors.New("userinfo_failed")
	}
	if strings.TrimSpace(identity.Email) == "" && strings.TrimSpace(cfg.EmailFallbackURL) != "" {
		var fallbackRoot any
		if err := oauth2GetJSON(r, cfg.EmailFallbackURL, token, cfg.EmailFallbackAccept, &fallbackRoot); err == nil {
			email, verified := selectPrimaryVerifiedEmail(fallbackRoot)
			identity.Email = email
			identity.EmailVerified = verified
		}
	}
	return oauth2UserInfo{
		Subject:       identity.Subject,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified && strings.TrimSpace(identity.Email) != "",
		Preferred:     identity.PreferredUsername,
		Display:       identity.DisplayName,
	}, nil
}

// selectPrimaryVerifiedEmail picks the primary, verified address from a GitHub
// /user/emails-style JSON array of {email, primary, verified} entries. It returns
// verified=true only for a selected entry, so an unverified primary can never be
// promoted to verified (AK security audit F4).
func selectPrimaryVerifiedEmail(root any) (string, bool) {
	items, ok := root.([]any)
	if !ok {
		return "", false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		primary, _ := m["primary"].(bool)
		verified, _ := m["verified"].(bool)
		if primary && verified {
			email, _ := m["email"].(string)
			return strings.TrimSpace(email), verified
		}
	}
	return "", false
}

func oauth2GetJSON(r *http.Request, url string, token oauth2TokenResp, accept string, out any) error {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if strings.TrimSpace(accept) != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)
	resp, err := defaultOutboundHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("userinfo_failed")
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("userinfo_failed")
	}
	return nil
}
