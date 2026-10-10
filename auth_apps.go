package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/auth"
)

// Remote applications.
//
// A remote application is an external issuer controlled by one group,
// addressed by its id (iam.AppByID) or its issuer (iam.AppByIssuer): the
// registry a resource server reads to trust that issuer's access tokens, its
// role in the group their ceiling. AuthKit itself accepts no token it
// signs. Every mutation takes an auth.Identity: registering one needs
// <persona>:credentials:manage in the group; changing or deleting an existing
// one also needs coverage of every role it holds, because whoever controls its
// keys acts as it. Only the system registers applications a group cannot
// change (trust root manual).

// UpsertRemoteApplication registers the issuer app.Issuer in the group ref,
// or updates it there. TrustRoot is the system's to set; other identities
// register at trust root user.
func (a *Client) UpsertRemoteApplication(ctx context.Context, who auth.Identity, ref iam.GroupRef, app iam.RemoteApplication, opts ...Option) (iam.RemoteApplication, error) {
	return a.ops.UpsertRemoteApplication(ctx, who, ref, app, opts...)
}

// DeleteRemoteApplication deletes the application id that ref controls; an
// id unknown in ref is iam.ErrRemoteApplicationNotFound. Only the system
// deletes a system-registered application.
func (a *Client) DeleteRemoteApplication(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, opts ...Option) error {
	return a.ops.DeleteRemoteApplication(ctx, who, ref, id, opts...)
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

// DeclareRemoteApplications makes apps the group ref's declared remote
// applications, as Config.RemoteApplications does for root: the system
// registers each (Issuer, JWKSURI or PublicKeys, Enabled) in ref with Role as
// its role there, none when zero, and disables the ones this deployment
// declared in ref before and no longer lists. A host whose groups are made
// after New (a merchant's) declares them once the group exists.
func (a *Client) DeclareRemoteApplications(ctx context.Context, ref iam.GroupRef, apps []iam.RemoteApplication, opts ...Option) error {
	return a.ops.DeclareRemoteApplications(ctx, ref, apps, opts...)
}
