// Package userinfo is how a library reads people's current email, name and
// username from the host's directory in process, importing neither the other.
// Values are current at read time; the reader keeps no copy and asks again
// when it needs them.
package userinfo

import "context"

// User is a person as the host's directory holds them now.
type User struct {
	// ID is the subject id the host's auth reports (auth.Identity.Subject).
	ID       string
	Email    string
	Name     string // display name
	Username string
}

// Lookup is the host's directory. It is safe for concurrent use. Each read
// returns the current values; a caller keeps no copy. An error means the
// directory could not answer and says nothing about any id.
type Lookup interface {
	// Get returns the users of ids, keyed by ID. An id the directory does not
	// hold (never issued, malformed or deleted) is absent, not an error.
	Get(ctx context.Context, ids []string) (map[string]User, error)
	// Search returns the users whose email, username or name contains query,
	// ignoring case: each once, as many as match up to limit. query is
	// literal text, never a pattern. An empty query or a limit below 1
	// returns none.
	Search(ctx context.Context, query string, limit int) ([]User, error)
}
