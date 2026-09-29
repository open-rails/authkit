package iam

import (
	"regexp"
	"strings"
)

// slugRe admits lowercase alnum with internal hyphens/dots (DNS-name shaped);
// max 253, no consecutive dots.
var slugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

// ValidSlug reports whether slug is a well-formed DNS-name-shaped identifier.
// Remote-application and permission-group instance slugs share exactly this
// shape; each caller owns the error it maps a rejection to.
func ValidSlug(slug string) bool {
	return len(slug) <= 253 && slugRe.MatchString(slug) && !strings.Contains(slug, "..")
}
