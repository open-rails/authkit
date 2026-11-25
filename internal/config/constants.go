package config

import "time"

// AuthKit's fixed lifetimes and policies.
const (
	// AccessTokenTTL is every access token's lifetime, a session's and the
	// authorization server's: the longest a revoked session's token passes
	// stateless checks.
	AccessTokenTTL = 15 * time.Minute
	// SessionTTL is a refresh session's lifetime from sign-in.
	SessionTTL = 30 * 24 * time.Hour
	// RefreshRotationGrace is how long a just-rotated refresh token is
	// answered with its successor instead of read as reuse: two holders of
	// one token refreshing at once (a shared credential file, a retry).
	RefreshRotationGrace = 30 * time.Second
	// PersonalAccessTokenTTL is a personal access token's lifetime when its
	// request names none; PersonalAccessTokenMaxTTL its ceiling.
	PersonalAccessTokenTTL    = 30 * 24 * time.Hour
	PersonalAccessTokenMaxTTL = 90 * 24 * time.Hour
	// CleanupInterval is how often expired auth state is cleaned up.
	CleanupInterval = time.Hour
	// PasswordMinLength and PasswordMaxLength bound a password in Unicode
	// code points (NIST SP 800-63B-4 §3.1.1.2): no composition rules, and
	// AuthKit's common-password blocklist always applies.
	PasswordMinLength = 8
	PasswordMaxLength = 128
)

// SignUpAgreements are the keys of the agreements every sign-up accepts.
func SignUpAgreements(c Config) []string {
	var keys []string
	for _, a := range c.Agreements {
		if a.SignUp {
			keys = append(keys, a.Key)
		}
	}
	return keys
}

// GroupClientAgreements are the keys of the agreements a user accepts before
// approving a group's OAuth client.
func GroupClientAgreements(c Config) []string {
	var keys []string
	for _, a := range c.Agreements {
		if a.GroupClients {
			keys = append(keys, a.Key)
		}
	}
	return keys
}
