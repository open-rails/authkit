package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
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
// account may revoke its own. Issued access tokens expire on their TTL.
func (a *Client) RevokeAccountSessions(ctx context.Context, actor iam.Actor, userID string) (iam.AccountSessionRevocation, error) {
	return a.engine.RevokeAccountSessions(ctx, actor, userID)
}

// MintAccessToken mints an access token for a live account outside any login
// flow; reserved claims are dropped. Host operation: your code decides.
func (a *Client) MintAccessToken(ctx context.Context, userID string, o iam.AccessTokenOptions) (iam.Token, error) {
	return a.engine.MintAccessToken(ctx, userID, o)
}
