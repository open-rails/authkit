package core

import "time"

// AcceptConfig configures verification of third-party JWTs (verify-only mode).
type AcceptConfig struct {
	Issuers    []IssuerAccept
	Skew       time.Duration
	Algorithms []string
}

// IssuerAccept describes how to accept tokens from a specific issuer.
type IssuerAccept struct {
	Issuer string
	// Audiences enforces that verified access tokens contain at least one of
	// these audiences. Prefer this over Audience for new integrations.
	Audiences []string
	// Audience enforces a single required audience for this issuer.
	// Deprecated: prefer Audiences.
	Audience     string
	JWKSURL      string
	PinnedRSAPEM string // optional PEM for degraded fallback
	CacheTTL     time.Duration
	MaxStale     time.Duration
}
