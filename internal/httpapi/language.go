package httpapi

import (
	"net/http"
	"slices"
	"strings"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/lang"
)

// langSelector is the fixed query parameter AuthKit reads for the request
// language (#143).
const langSelector = "lang"

// acceptable reports whether code is one of the supported languages (any, when
// none are declared).
func acceptable(c config.LanguageConfig, code string) bool {
	return code != "" && (len(c.Supported) == 0 || slices.Contains(c.Supported, code))
}

// requestLanguage is the language contract: `?lang` > the first acceptable
// Accept-Language entry > Languages.Default. Routes are never mounted under a
// language prefix and AuthKit sets no language cookie (#236).
func requestLanguage(r *http.Request, c config.LanguageConfig) string {
	if code := lang.Normalize(r.URL.Query().Get(langSelector)); acceptable(c, code) {
		return code
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, _, _ := strings.Cut(part, ";")
		if code := lang.Normalize(tag); acceptable(c, code) {
			return code
		}
	}
	return c.Default
}

// languageMiddleware attaches the request language for the engine's messages.
func (s *Service) languageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(lang.WithRequest(r.Context(), requestLanguage(r, s.cfg.Languages))))
	})
}
