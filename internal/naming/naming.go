// Package naming applies the username rule of a normalized
// config.UsernameConfig: validation, derivation, renames and former names.
package naming

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
)

// UsernamePattern is the fixed character rule for interactive usernames,
// compatible with Go RE2 and JavaScript `u`/`v` regular expressions and HTML
// `pattern`. Length is governed separately.
const UsernamePattern = "^[A-Za-z][A-Za-z0-9_]*$"

// Validate checks a trimmed username against the length rule and
// UsernamePattern. Length failures carry min_length/max_length metadata.
func Validate(c config.UsernameConfig, username string) error {
	return validate(c.MinLength, c.MaxLength, username, false)
}

// ValidateImport checks a host-provisioned username: the configured minimum,
// a maximum of at least 64, and hyphens are also allowed.
func ValidateImport(c config.UsernameConfig, username string) error {
	return validate(c.MinLength, max(c.MaxLength, config.UsernameMaxLengthCeiling), username, true)
}

func validate(minLen, maxLen int, username string, hyphens bool) error {
	username = strings.TrimSpace(username)
	if n := utf8.RuneCountInString(username); n < minLen || n > maxLen {
		code := errmodel.CodeUsernameTooShort
		if n > maxLen {
			code = errmodel.CodeUsernameTooLong
		}
		return errmodel.E(code, errmodel.WithMetadata(map[string]any{"min_length": minLen, "max_length": maxLen}))
	}
	if !asciiLetter(username[0]) {
		return errmodel.E(errmodel.CodeUsernameMustStartWithLetter)
	}
	if strings.Contains(username, "@") {
		return errmodel.E(errmodel.CodeUsernameCannotContainAt)
	}
	for i := 0; i < len(username); i++ {
		if c := username[i]; !asciiLetter(c) && !(c >= '0' && c <= '9') && c != '_' && !(hyphens && c == '-') {
			return errmodel.E(errmodel.CodeUsernameInvalidCharacters)
		}
	}
	return nil
}

// Derive turns arbitrary text into a username that satisfies Validate.
func Derive(c config.UsernameConfig, s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "user"
	}
	if !asciiLetter(out[0]) {
		out = "u" + out
	}
	for len(out) < c.MinLength {
		out += "_user"
	}
	return out[:min(len(out), c.MaxLength)]
}

// WithSuffix appends suffix to a derived username, trimming base (and, under a
// very small maximum, suffix) so the result still satisfies Validate.
func WithSuffix(c config.UsernameConfig, base, suffix string) string {
	keep := max(1, c.MaxLength-len(suffix))
	if len(base) > keep {
		base = base[:keep]
	}
	out := base + suffix
	return out[:min(len(out), c.MaxLength)]
}

func asciiLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// CheckRename runs under the account lock. Callers authorize and detect a
// same-canonical-name no-op first. Trusted import updates skip it, never
// namespace ownership checks.
func CheckRename(c config.UsernameConfig, lastRenamedAt *time.Time, now time.Time) error {
	if !c.Renames {
		return iam.ErrRenamesDisabled
	}
	if next, ok := nextRename(c, lastRenamedAt); ok && now.Before(next) {
		return errmodel.E(errmodel.CodeRenameRateLimited, errmodel.WithMeta("next_rename_at", next))
	}
	return nil
}

func nextRename(c config.UsernameConfig, last *time.Time) (time.Time, bool) {
	if last == nil || c.RenameInterval <= 0 {
		return time.Time{}, false
	}
	return last.Add(c.RenameInterval), true
}

// Cooldown is the least time between two renames.
func Cooldown(c config.UsernameConfig) time.Duration { return max(c.RenameInterval, 0) }

// FormerNameExpiresAt is the promise made at rename time: nil means forever,
// and immediate returns now (lookups and claims use the same strict
// now.Before(deadline)). Later policy changes never rewrite it.
func FormerNameExpiresAt(c config.UsernameConfig, now time.Time) *time.Time {
	switch c.FormerNames.Mode {
	case config.FormerNamesForever:
		return nil
	case config.FormerNamesImmediate:
		return &now
	}
	deadline := now.Add(c.FormerNames.Duration)
	return &deadline
}

// Alias is a former username that still resolves to its owner.
type Alias struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// PolicyInfo is the rename policy account UIs show. Timing is reported by
// State.NextRenameAt and RetryAfterSeconds.
type PolicyInfo struct {
	Enabled                    bool                   `json:"enabled"`
	FormerNameRetentionMode    config.FormerNamesMode `json:"former_name_retention_mode"`
	FormerNameRetentionSeconds float64                `json:"former_name_retention_seconds"`
}

// State is an account's rename state.
type State struct {
	Aliases           []Alias    `json:"aliases,omitempty"`
	Policy            PolicyInfo `json:"policy"`
	Allowed           bool       `json:"allowed"`
	NextRenameAt      *time.Time `json:"next_rename_at,omitempty"`
	RetryAfterSeconds int64      `json:"retry_after_seconds"`
}

// NewState is the rename state of an account last renamed at last.
func NewState(c config.UsernameConfig, last *time.Time, now time.Time) State {
	retention := c.FormerNames.Duration
	if c.FormerNames.Mode != config.FormerNamesFinite {
		retention = 0
	}
	out := State{Policy: PolicyInfo{
		Enabled: c.Renames, FormerNameRetentionMode: c.FormerNames.Mode,
		FormerNameRetentionSeconds: retention.Seconds(),
	}, Allowed: c.Renames}
	if next, ok := nextRename(c, last); ok {
		out.NextRenameAt = &next
		if next.After(now) {
			out.Allowed = false
			remaining := next.Sub(now)
			out.RetryAfterSeconds = int64(remaining / time.Second)
			if remaining%time.Second != 0 {
				out.RetryAfterSeconds++
			}
		}
	}
	return out
}
