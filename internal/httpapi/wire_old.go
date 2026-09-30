package httpapi

import "github.com/open-rails/authkit/iam"

// Wire types the v1 contract dropped; each goes with its last handler use.

// StepUpResult is a re-authenticated session: a fresh access token whose
// assurance claims match the session.
type StepUpResult struct {
	TokenSet  iam.TokenSet `json:"token_set"`
	FreshAuth FreshAuth    `json:"fresh_auth"`
}
