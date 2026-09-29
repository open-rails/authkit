package authflow

import (
	"regexp"
	"strings"

	"github.com/open-rails/authkit/internal/errmodel"
)

var preferredLanguageRe = regexp.MustCompile(`^[A-Za-z]{2}$`)

func NormalizePreferredLanguage(language string) (string, error) {
	language = strings.TrimSpace(strings.ToLower(language))
	if language == "" {
		return "", nil
	}
	if !preferredLanguageRe.MatchString(language) {
		return "", errmodel.E(errmodel.CodeInvalidPreferredLanguage)
	}
	return language, nil
}
