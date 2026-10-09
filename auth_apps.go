package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// Remote applications, delegation and service JWTs.
//
// A remote application is an external issuer controlled by one group,
// addressed by its id (iam.AppByID) or its issuer (iam.AppByIssuer). Every
// mutation takes an iam.Actor: registering one needs
// <persona>:credentials:manage in the group; changing or deleting an existing
// one also needs coverage of every role it holds, because whoever controls its
// keys acts as it. Only the system registers applications a group cannot
// change (trust root manual).

// UpsertRemoteApplication registers the issuer app.Issuer in the group ref,
// or updates it there. TrustRoot is the system's to set; other actors
// register at trust root user.
func (a *Client) UpsertRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, app iam.RemoteApplication, opts ...Option) (iam.RemoteApplication, error) {
	return a.ops.UpsertRemoteApplication(ctx, actor, ref, app, opts...)
}

// DeleteRemoteApplication deletes the application id that ref controls; an
// id unknown in ref is iam.ErrRemoteApplicationNotFound. Only the system
// deletes a system-registered application.
func (a *Client) DeleteRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string, opts ...Option) error {
	return a.ops.DeleteRemoteApplication(ctx, actor, ref, id, opts...)
}

// RemoteApplication returns one application, disabled ones included
// (Enabled), with its role in its group and the permissions that role confers
// now; else iam.ErrRemoteApplicationNotFound.
func (a *Client) RemoteApplication(ctx context.Context, ref iam.AppRef) (iam.RemoteApplication, error) {
	return a.ops.RemoteApplication(ctx, ref)
}

// ListRemoteApplications lists the applications ref controls, newest first.
func (a *Client) ListRemoteApplications(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error) {
	return a.ops.ListRemoteApplications(ctx, ref, p)
}

// MintDelegatedAccessToken signs a delegated access token as this deployment.
// A user actor mints only for itself, and every AuthKit permission in
// d.Permissions must be held live by it on the root group
// (iam.ErrDelegationRefused otherwise). The system mints for any subject.
//
// Deprecated: delegated access tokens are superseded by the authorization
// server's RFC 9068 access tokens (token exchange for a user, client
// credentials for a machine) and are removed in v2.
func (a *Client) MintDelegatedAccessToken(ctx context.Context, actor iam.Actor, d iam.DelegatedAccess, opts ...Option) (iam.Token, error) {
	return a.ops.MintDelegatedAccessToken(ctx, actor, d, opts...)
}

// MintServiceJWT signs a first-party service JWT with this deployment's key.
// It grants nothing AuthKit enforces; the receiver authorizes it.
func (a *Client) MintServiceJWT(ctx context.Context, s iam.ServiceJWT, opts ...Option) (iam.Token, iam.ServiceJWTClaims, error) {
	return a.ops.MintServiceJWT(ctx, s, opts...)
}
