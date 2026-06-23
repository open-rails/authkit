package oidckit

import "time"

// Claims is a minimal set of user identity fields extracted from the ID token/userinfo.
type Claims struct {
	Subject           string
	Email             *string
	EmailVerified     *bool
	Name              *string
	PreferredUsername *string
	AuthTime          time.Time
	RawIDToken        string
}
