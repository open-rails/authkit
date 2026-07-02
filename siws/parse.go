package siws

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// headerRegex matches the SIWS header line: "${domain} wants you to sign in
// with your Solana account:". Compiled once at package load.
var headerRegex = regexp.MustCompile(`^(.+) wants you to sign in with your Solana account:$`)

// ParseMessage extracts SignInInput fields from a SIWS message string.
// This is useful for verifying the signed message matches expected values.
func ParseMessage(message string) (SignInInput, error) {
	var input SignInInput

	lines := strings.Split(message, "\n")
	if len(lines) < 2 {
		return input, fmt.Errorf("message too short")
	}

	// Parse header: "${domain} wants you to sign in with your Solana account:"
	matches := headerRegex.FindStringSubmatch(lines[0])
	if matches == nil {
		return input, fmt.Errorf("invalid header format")
	}
	input.Domain = matches[1]

	// Line 2 is the address
	input.Address = strings.TrimSpace(lines[1])
	if input.Address == "" {
		return input, fmt.Errorf("missing address")
	}

	// Find where the fields section starts (look for "URI:", "Version:", "Nonce:", etc.)
	fieldsStart := -1
	for i := 2; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "URI:") ||
			strings.HasPrefix(line, "Version:") ||
			strings.HasPrefix(line, "Chain ID:") ||
			strings.HasPrefix(line, "Nonce:") ||
			strings.HasPrefix(line, "Issued At:") {
			fieldsStart = i
			break
		}
	}

	// Extract statement (everything between address and fields)
	if fieldsStart > 2 {
		var statementLines []string
		for i := 2; i < fieldsStart; i++ {
			line := lines[i]
			// Skip empty lines at the beginning
			if len(statementLines) == 0 && strings.TrimSpace(line) == "" {
				continue
			}
			statementLines = append(statementLines, line)
		}
		if len(statementLines) > 0 {
			statement := strings.Join(statementLines, "\n")
			statement = strings.TrimSpace(statement)
			if statement != "" {
				input.Statement = &statement
			}
		}
	}

	// Parse fields
	inResources := false
	var resources []string

	for i := fieldsStart; i < len(lines) && fieldsStart > 0; i++ {
		line := lines[i]

		if strings.HasPrefix(line, "- ") && inResources {
			resources = append(resources, strings.TrimPrefix(line, "- "))
			continue
		}

		if strings.HasPrefix(line, "Resources:") {
			inResources = true
			continue
		}

		inResources = false

		if strings.HasPrefix(line, "URI: ") {
			uri := strings.TrimPrefix(line, "URI: ")
			input.URI = &uri
		} else if strings.HasPrefix(line, "Version: ") {
			version := strings.TrimPrefix(line, "Version: ")
			input.Version = &version
		} else if strings.HasPrefix(line, "Chain ID: ") {
			chainID := strings.TrimPrefix(line, "Chain ID: ")
			input.ChainID = &chainID
		} else if strings.HasPrefix(line, "Nonce: ") {
			input.Nonce = strings.TrimPrefix(line, "Nonce: ")
		} else if strings.HasPrefix(line, "Issued At: ") {
			input.IssuedAt = strings.TrimPrefix(line, "Issued At: ")
		} else if strings.HasPrefix(line, "Expiration Time: ") {
			exp := strings.TrimPrefix(line, "Expiration Time: ")
			input.ExpirationTime = &exp
		} else if strings.HasPrefix(line, "Not Before: ") {
			nb := strings.TrimPrefix(line, "Not Before: ")
			input.NotBefore = &nb
		} else if strings.HasPrefix(line, "Request ID: ") {
			rid := strings.TrimPrefix(line, "Request ID: ")
			input.RequestID = &rid
		}
	}

	if len(resources) > 0 {
		input.Resources = resources
	}

	return input, nil
}

// ValidateTimestamps checks that the message timestamps are valid.
// Returns an error if the message is expired or not yet valid.
func ValidateTimestamps(input SignInInput) error {
	now := time.Now().UTC()

	// Check expiration
	if input.ExpirationTime != nil && *input.ExpirationTime != "" {
		exp, err := time.Parse(time.RFC3339, *input.ExpirationTime)
		if err != nil {
			return fmt.Errorf("invalid expiration time format: %w", err)
		}
		if now.After(exp) {
			return fmt.Errorf("message expired at %s", *input.ExpirationTime)
		}
	}

	// Check not-before
	if input.NotBefore != nil && *input.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, *input.NotBefore)
		if err != nil {
			return fmt.Errorf("invalid not-before time format: %w", err)
		}
		if now.Before(nb) {
			return fmt.Errorf("message not valid until %s", *input.NotBefore)
		}
	}

	// Check issued-at is not too far in the future (allow 5 min clock skew)
	if input.IssuedAt != "" {
		issued, err := time.Parse(time.RFC3339, input.IssuedAt)
		if err != nil {
			return fmt.Errorf("invalid issued-at time format: %w", err)
		}
		if issued.After(now.Add(5 * time.Minute)) {
			return fmt.Errorf("message issued in the future: %s", input.IssuedAt)
		}
	}

	return nil
}

// ValidateDomain checks that the message domain matches the expected domain.
func ValidateDomain(input SignInInput, expectedDomain string) error {
	if input.Domain != expectedDomain {
		return fmt.Errorf("domain mismatch: got %s, expected %s", input.Domain, expectedDomain)
	}
	return nil
}
