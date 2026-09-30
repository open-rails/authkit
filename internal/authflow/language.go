package authflow

import (
	"strings"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/lang"
)

// NormalizePreferredLanguage is lang.Normalize for an account's stored
// preference: "" clears it, and a value naming no language is refused.
func NormalizePreferredLanguage(language string) (string, error) {
	if strings.TrimSpace(language) == "" {
		return "", nil
	}
	if l := lang.Normalize(language); l != "" {
		return l, nil
	}
	return "", errmodel.E(errmodel.CodeInvalidPreferredLanguage)
}
