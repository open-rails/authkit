package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// Sessions and access tokens.

// Sessions lists the account's live refresh sessions on this issuer.
func (a *Client) Sessions(ctx context.Context, userID string) ([]iam.Session, error) {
	return a.ops.Sessions(ctx, userID)
}

// ListSessionEvents pages the account's sign-in and session history, newest
// first: sign-ins, failed sign-ins, revocations and password changes.
func (a *Client) ListSessionEvents(ctx context.Context, userID string, q iam.SessionEventQuery) (iam.ListPage[iam.SessionEvent], error) {
	return a.ops.ListSessionEvents(ctx, userID, q)
}

// RevokeSession revokes one refresh session under ACCT(root:users:manage),
// where covering a peer suffices; an account may revoke its own.
func (a *Client) RevokeSession(ctx context.Context, who auth.Identity, userID, sessionID string, opts ...Option) error {
	return a.ops.RevokeSession(ctx, who, userID, sessionID, opts...)
}

// RevokeAccountSessions revokes the account's refresh sessions on every
// account issuer, its device keys and its offline OAuth grants, under
// ACCT(root:users:manage), where covering a peer suffices, so staff can
// contain a compromised peer; an account may revoke its own. It records iam.EventUserSessionsRevoked. Their
// access tokens are refused at once by every session check (permission
// checks, verify.Sensitive, account changes) and pass stateless verification
// until they expire.
func (a *Client) RevokeAccountSessions(ctx context.Context, who auth.Identity, userID string, opts ...Option) (iam.AccountSessionRevocation, error) {
	return a.ops.RevokeAccountSessions(ctx, who, userID, opts...)
}

// RevokeOAuthGrant ends a consented OAuth grant, named by the grant id the
// grant authorizer (Deps.OAuthGrants) is given: its refresh tokens stop
// working at once, and its access tokens expire on their own. An unknown or
// ended grant is not an error. Host operation: your code decides.
func (a *Client) RevokeOAuthGrant(ctx context.Context, grantID string, opts ...Option) error {
	return a.ops.RevokeOAuthGrant(ctx, grantID, opts...)
}

// MintAccessToken mints an access token for a live account outside any login
// flow. A claim in o.Claims named like one of AuthKit's own
// (docs/stability.md) is refused with invalid_request. Host operation: your
// code decides.
func (a *Client) MintAccessToken(ctx context.Context, userID string, o iam.AccessTokenOptions, opts ...Option) (iam.Token, error) {
	return a.ops.MintAccessToken(ctx, userID, o, opts...)
}

// CheckSession is the gate verify.RequireSession applies, for callers holding
// verified claims: nil when the session or device key cl was minted from is
// still active, else iam.ErrSessionRevoked. A user's token names one, and so
// does a delegated token minted from a sign-in (MintDelegatedAccessToken with
// a session-bound identity); a token minted without one is refused. Any other
// credential is forbidden.
func (a *Client) CheckSession(ctx context.Context, cl verify.Claims) error {
	return a.ops.CheckSession(ctx, cl)
}

// CheckRecentSignIn is the gate verify.Sensitive applies: CheckSession, and
// the user's own token, signed in within the last 15 minutes, with the second
// factor when the account has one; otherwise step_up_required (its metadata
// lists the account's step-up methods). A delegated token is forbidden.
func (a *Client) CheckRecentSignIn(ctx context.Context, cl verify.Claims) error {
	return a.ops.CheckRecentSignIn(ctx, cl)
}
