package iam

import "time"

// Token is a signed token and the moment it expires.
type Token struct {
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}
