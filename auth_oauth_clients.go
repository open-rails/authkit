package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/auth"
)

// Group OAuth clients. A group of a persona declared with OAuthClients
// registers OAuth clients (RFC 7591 metadata) that sign its users in here,
// such as a merchant's "Sign in with openrails.dev". They are third-party:
// each user consents to the scopes one asks for, it gets only proven contact
// claims, and its tokens act only in its group. Changes take CAP
// <persona>:credentials:manage in the group (rule ACCT does not apply).

// CreateGroupOAuthClient registers an OAuth client in the group. A
// client_secret_basic client's secret is in the answer this once. A group
// holds at most iam.MaxGroupOAuthClients.
func (a *Client) CreateGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, n iam.NewOAuthClient, opts ...Option) (iam.OAuthClientCreated, error) {
	return a.ops.CreateGroupOAuthClient(ctx, who, ref, n, opts...)
}

// GroupOAuthClients returns the group's OAuth clients, oldest first.
func (a *Client) GroupOAuthClients(ctx context.Context, ref iam.GroupRef) ([]iam.OAuthClient, error) {
	return a.ops.GroupOAuthClients(ctx, ref)
}

// GroupOAuthClient returns one of the group's OAuth clients, else
// iam.ErrOAuthClientNotFound.
func (a *Client) GroupOAuthClient(ctx context.Context, ref iam.GroupRef, clientID string) (iam.OAuthClient, error) {
	return a.ops.GroupOAuthClient(ctx, ref, clientID)
}

// UpdateGroupOAuthClient changes one of the group's OAuth clients. Disabled
// refuses its sign-ins, and every token it holds at its next use.
func (a *Client) UpdateGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, clientID string, u iam.OAuthClientUpdate, opts ...Option) (iam.OAuthClient, error) {
	return a.ops.UpdateGroupOAuthClient(ctx, who, ref, clientID, u, opts...)
}

// RotateGroupOAuthClientSecret replaces a client_secret_basic client's
// secret and returns the new one this once; the old one stops at once.
func (a *Client) RotateGroupOAuthClientSecret(ctx context.Context, who auth.Identity, ref iam.GroupRef, clientID string, opts ...Option) (string, error) {
	return a.ops.RotateGroupOAuthClientSecret(ctx, who, ref, clientID, opts...)
}

// DeleteGroupOAuthClient deletes one of the group's OAuth clients and every
// consent to it; its tokens are refused at their next use. Deleting the
// group deletes its clients.
func (a *Client) DeleteGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, clientID string, opts ...Option) error {
	return a.ops.DeleteGroupOAuthClient(ctx, who, ref, clientID, opts...)
}

// OAuthConsents returns the group clients the user consented to (their
// "connected apps"), newest change first.
func (a *Client) OAuthConsents(ctx context.Context, userID string) ([]iam.OAuthConsent, error) {
	return a.ops.OAuthConsents(ctx, userID)
}

// RevokeConsent withdraws the user's consent to a group client, as the host
// (unlinking a merchant): the client's refresh tokens for the user end at
// their next use, its back-channel logout is sent when it registered one,
// and oauth_consent.revoked is recorded. iam.ErrOAuthConsentNotFound when
// there is none.
func (a *Client) RevokeConsent(ctx context.Context, userID, clientID string, opts ...Option) error {
	return a.ops.RevokeConsent(ctx, userID, clientID, opts...)
}
