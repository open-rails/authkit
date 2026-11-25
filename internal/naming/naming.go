// Package naming applies AuthKit's username rule and its naming policy
// (github.com/open-rails/authkit/naming): validation, derivation, renames
// and name retention.
package naming

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/naming"
)

// Username lengths: MinLength to MaxLength, MaxImportLength for a
// host-provisioned name.
const (
	MinLength       = 4
	MaxLength       = 30
	MaxImportLength = 64
)

// Retention is how long a name its owner let go of stays reserved: Forever,
// or For.
type Retention struct {
	Forever bool
	For     time.Duration
}

// FormerNames and DeletedNames are the policy's retentions: a name renamed
// away from forwards for naming.FormerNameReservation; a deleted owner's
// stays reserved forever.
var (
	FormerNames  = Retention{For: naming.FormerNameReservation}
	DeletedNames = Retention{Forever: true}
)

// UsernamePattern is the fixed character rule for interactive usernames,
// compatible with Go RE2 and JavaScript `u`/`v` regular expressions and HTML
// `pattern`. Length is governed separately.
const UsernamePattern = "^[A-Za-z][A-Za-z0-9_]*$"

// Canonical is the one stored and displayed form of a local username.
// Legacy mixed-case records still resolve through the case-insensitive claims.
func Canonical(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

// Validate checks a trimmed username against the length rule and
// UsernamePattern. Length failures carry min_length/max_length metadata.
func Validate(username string) error {
	return validate(MinLength, MaxLength, username, false)
}

// ValidateImport checks a host-provisioned username: up to MaxImportLength,
// and hyphens are also allowed.
func ValidateImport(username string) error {
	return validate(MinLength, MaxImportLength, username, true)
}

func validate(minLen, maxLen int, username string, hyphens bool) error {
	username = strings.TrimSpace(username)
	if n := utf8.RuneCountInString(username); n < minLen || n > maxLen {
		code := errmodel.CodeUsernameTooShort
		if n > maxLen {
			code = errmodel.CodeUsernameTooLong
		}
		return errmodel.E(code, errmodel.WithDetails(errmodel.LengthBounds{MinLength: minLen, MaxLength: maxLen}))
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
func Derive(s string) string {
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
	for len(out) < MinLength {
		out += "_user"
	}
	return out[:min(len(out), MaxLength)]
}

// WithSuffix appends suffix to a derived username, trimming base (and, under a
// very small maximum, suffix) so the result still satisfies Validate.
func WithSuffix(base, suffix string) string {
	keep := max(1, MaxLength-len(suffix))
	if len(base) > keep {
		base = base[:keep]
	}
	out := base + suffix
	return out[:min(len(out), MaxLength)]
}

func asciiLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// CheckRename runs under the account lock. Callers authorize and detect a
// same-canonical-name no-op first. Trusted import updates skip it, never
// namespace ownership checks.
func CheckRename(lastRenamedAt *time.Time, now time.Time) error {
	if lastRenamedAt == nil {
		return nil
	}
	if next := naming.NextRename(*lastRenamedAt); now.Before(next) {
		next = next.UTC()
		retry := int64((next.Sub(now) + time.Second - time.Nanosecond) / time.Second)
		cooldown := int64(naming.RenameCooldown / time.Second)
		return errmodel.E(errmodel.CodeRenameRateLimited, errmodel.WithDetails(errmodel.ActionAvailability{
			Action: "update_username", Reason: "cooldown", RetryAfterSeconds: retry, NextAllowedAt: &next, CooldownSeconds: &cooldown,
		}))
	}
	return nil
}

// ExpiresAt is the promise made when a name is let go of: nil means forever.
// Later policy changes never rewrite it.
func ExpiresAt(r Retention, now time.Time) *time.Time {
	if r.Forever {
		return nil
	}
	deadline := now.Add(r.For)
	return &deadline
}

// Alias is a former username that still resolves to its owner.
type Alias struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// PolicyInfo is the naming policy account UIs show: renames, and how long a
// renamed-away or purged account's name stays reserved ("finite" with its
// seconds, or "forever" with 0). Rename timing is reported by
// State.NextRenameAt and RetryAfterSeconds.
type PolicyInfo struct {
	Enabled                     bool   `json:"enabled"`
	FormerNameRetentionMode     string `json:"former_name_retention_mode"`
	FormerNameRetentionSeconds  int64  `json:"former_name_retention_seconds"`
	DeletedNameRetentionMode    string `json:"deleted_name_retention_mode"`
	DeletedNameRetentionSeconds int64  `json:"deleted_name_retention_seconds"`
}

// State is an account's rename state.
type State struct {
	Aliases           []Alias    `json:"aliases"`
	Policy            PolicyInfo `json:"policy"`
	Allowed           bool       `json:"allowed"`
	NextRenameAt      *time.Time `json:"next_rename_at"`
	RetryAfterSeconds int64      `json:"retry_after_seconds"`
}

// Policy is the policy as PolicyInfo shows it.
var Policy = PolicyInfo{
	Enabled:                    true,
	FormerNameRetentionMode:    "finite",
	FormerNameRetentionSeconds: int64(naming.FormerNameReservation / time.Second),
	DeletedNameRetentionMode:   "forever",
}

// NewState is the rename state of an account last renamed at last.
func NewState(last *time.Time, now time.Time) State {
	out := State{Policy: Policy, Allowed: true}
	if last != nil {
		next := naming.NextRename(*last)
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
