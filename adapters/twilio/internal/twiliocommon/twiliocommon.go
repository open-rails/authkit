// Package twiliocommon holds the small helpers shared by AuthKit's Twilio email
// and SMS sender adapters (which are separate packages): request-language
// resolution, the app display label, and the default outbound HTTP client.
package twiliocommon

import (
	"context"
	"net/http"
	"strings"
	"time"

	authlang "github.com/open-rails/authkit/lang"
)

// ContextLanguage resolves the request's language to a supported sender locale,
// falling back to "en" (only "es" is otherwise supported today).
func ContextLanguage(ctx context.Context) string {
	language, ok := authlang.LanguageFromContext(ctx)
	if !ok {
		return "en"
	}
	language = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(language, "_", "-")))
	if language == "" {
		return "en"
	}
	if i := strings.Index(language, "-"); i > 0 {
		language = language[:i]
	}
	switch language {
	case "es":
		return "es"
	default:
		return "en"
	}
}

// AppLabel returns the trimmed app name, or "Auth" when empty.
func AppLabel(name string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return "Auth"
}

// DefaultHTTPClient returns custom when non-nil, else a 10s-timeout client.
func DefaultHTTPClient(custom *http.Client) *http.Client {
	if custom != nil {
		return custom
	}
	return &http.Client{Timeout: 10 * time.Second}
}
