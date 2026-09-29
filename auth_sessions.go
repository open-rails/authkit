package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Sessions and access tokens.

// Sessions lists the account's live refresh sessions on this issuer.
func (a *Client) Sessions(ctx context.Context, userID string) ([]iam.Session, error) {
	return a.engine.Sessions(ctx, userID)
}

// SessionEvents pages the account's sign-in and session history, newest
// first: sign-ins, failed sign-ins, revocations and password changes.
func (a *Client) SessionEvents(ctx context.Context, userID string, q iam.SessionEventQuery) (iam.ListPage[iam.SessionEvent], error) {
	return a.engine.SessionEvents(ctx, userID, q)
}

// RevokeSession revokes one refresh session under ACCT(root:users:manage);
// an account may revoke its own.
func (a *Client) RevokeSession(ctx context.Context, actor iam.Actor, userID, sessionID string) error {
	return a.engine.RevokeSession(ctx, actor, userID, sessionID)
}

// RevokeAccountSessions revokes the account's refresh sessions on every
// account issuer and its device keys, under ACCT(root:users:manage); an
// account may revoke its own. Their access tokens are refused at once by
// every session check (permission checks, verify.Sensitive, account changes)
// and pass stateless verification until they expire.
func (a *Client) RevokeAccountSessions(ctx context.Context, actor iam.Actor, userID string) (iam.AccountSessionRevocation, error) {
	return a.engine.RevokeAccountSessions(ctx, actor, userID)
}

// MintAccessToken mints an access token for a live account outside any login
// flow; reserved claims are dropped. Host operation: your code decides.
func (a *Client) MintAccessToken(ctx context.Context, userID string, o iam.AccessTokenOptions) (iam.Token, error) {
	return a.engine.MintAccessToken(ctx, userID, o)
}

// CheckRecentSignIn is the gate verify.Sensitive applies, for callers holding
// verified claims: nil when the session or device key cl was minted from is
// still active and signed in within the last 15 minutes, with its second
// factor when the account has one. Otherwise it is iam.ErrSessionRevoked,
// step_up_required (its metadata lists the account's step-up methods), or
// forbidden for a credential that is not a user's.
func (a *Client) CheckRecentSignIn(ctx context.Context, cl verify.Claims) error {
	return a.engine.CheckRecentSignIn(ctx, cl)
}
