package verify

import (
	"context"
	"time"
)

// UserClaimsData is the shared local-user view for HTTP framework adapters.
// It is a projection of verified request claims, not a complete user record.
// Reading it performs no verification or database lookup. Except for UserID,
// fields may have their zero value because the claim was not supplied.
//
// Required and Optional use token claims as issued. AuthKit's ordinary access
// tokens omit profile fields. RequiredLive additionally checks account liveness
// and fills Email, EmailVerified, and Username from that request's lookup; it
// does not refresh entitlements, authentication assurance, or MFA enrollment.
type UserClaimsData struct {
	// UserID is the immutable ID in the verifier's trusted local user namespace.
	// It is nonempty when UserClaimsFromContext returns true.
	UserID string
	// Email is optional profile data. Empty does not establish that the account
	// has no email; it may simply not have been loaded into these claims.
	Email string
	// EmailVerified is false when absent as well as when unverified. Interpret
	// it with Email and the middleware's profile-loading contract.
	EmailVerified bool
	// Username is optional, mutable profile data; use UserID for ownership.
	Username string
	// SessionID identifies the refresh session when present. Sessionless user
	// credentials, such as device-key access tokens, may leave it empty.
	SessionID string
	// Entitlements is the issuer's token-time access-rights snapshot, normally
	// supplied by its entitlements provider. Nil may mean no provider, no grants,
	// or unavailable data. Changes after issuance are not reflected here.
	Entitlements []string
	// AMR lists the authentication methods reported for this authentication.
	// Nil means no methods were supplied. It does not describe every method
	// configured on the account.
	AMR []string
	// ACR is the issuer-defined authentication assurance class; empty means
	// unspecified. Interpret it using the trusted issuer's assurance policy.
	ACR string
	// AuthTime is when the represented authentication occurred, not when the
	// access token was refreshed. A zero time means the claim was absent.
	AuthTime time.Time
	// MFAEnrolled is the issuer's mfa_enrolled snapshot at token issuance.
	// False also represents an absent claim. True does not prove MFA was
	// performed for this authentication; use the assurance/step-up checks.
	MFAEnrolled bool
}

// UserClaimsFromContext reads a verified local user from middleware context.
// It returns false for missing claims, external subjects, and machine or
// delegated principals. Entitlements and AMR are copied so callers cannot
// mutate the underlying verified claims through the returned slices.
func UserClaimsFromContext(ctx context.Context) (UserClaimsData, bool) {
	if ctx == nil {
		return UserClaimsData{}, false
	}
	cl, ok := ClaimsFromContext(ctx)
	if !ok || !cl.IsUser() {
		return UserClaimsData{}, false
	}
	return UserClaimsData{
		UserID: cl.UserID, Email: cl.Email, EmailVerified: cl.EmailVerified,
		Username: cl.Username, SessionID: cl.SessionID,
		Entitlements: append([]string(nil), cl.Entitlements...),
		AMR:          append([]string(nil), cl.AMR...), ACR: cl.ACR,
		AuthTime: cl.AuthTime, MFAEnrolled: cl.MFAEnrolled,
	}, true
}
