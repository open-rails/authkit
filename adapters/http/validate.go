package authhttp

import (
	"fmt"
	"regexp"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func validateUsername(username string) error {
	username = strings.TrimSpace(username)

	if len(username) < 4 {
		return fmt.Errorf("username_too_short")
	}
	if len(username) > 30 {
		return fmt.Errorf("username_too_long")
	}

	if len(username) > 0 {
		b0 := username[0]
		isLetter := (b0 >= 'a' && b0 <= 'z') || (b0 >= 'A' && b0 <= 'Z')
		if !isLetter {
			return fmt.Errorf("username_must_start_with_letter")
		}
	}

	if strings.Contains(username, "@") {
		return fmt.Errorf("username_cannot_contain_at")
	}
	if strings.HasPrefix(username, "+") {
		return fmt.Errorf("username_cannot_start_with_plus")
	}

	validPattern := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validPattern.MatchString(username) {
		return fmt.Errorf("username_invalid_characters")
	}

	if core.IsReservedUsername(username) {
		return fmt.Errorf("username_reserved")
	}

	return nil
}
