package authkit

import (
	"context"

	"github.com/open-rails/authkit/verify"
)

// CheckCredential rechecks trusted, previously verified user claims against
// their original expiry and live account/session/group state. It grants no
// permission and does not require a recent sign-in. Never pass unverified claims;
// ordinary consumers call auth.CredentialChecker on the original Verified.
// API keys, PATs and credentials without supported native user authority refuse.
func (a *Client) CheckCredential(ctx context.Context, cl verify.Claims) error {
	return a.engine.CheckCredential(ctx, cl)
}

// CheckCredential is the live check for this verifier's previously verified
// native user claims, preserving the verifier's accepted effective deadline.
func (v *Verifier) CheckCredential(ctx context.Context, cl verify.Claims) error {
	return v.client.CheckCredential(ctx, cl)
}
