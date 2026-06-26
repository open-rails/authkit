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
	var identity authprovider.Identity
	var err error
	if cfg.IdentityMapper != nil {
		identity, err = cfg.IdentityMapper(root)
	} else {
		identity, err = authprovider.MapIdentity(root, cfg.UserMapping)
	}
	if err != nil {
		return oauth2UserInfo{}, errors.New("userinfo_failed")
	}
	if strings.TrimSpace(identity.Email) == "" && cfg.EmailFallback != nil {
		var fallbackRoot any
		if err := oauth2GetJSON(r, cfg.EmailFallback.URL, token, cfg.EmailFallback.Accept, &fallbackRoot); err == nil {
			email, verified := authprovider.MapFallbackEmail(fallbackRoot, *cfg.EmailFallback)
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
