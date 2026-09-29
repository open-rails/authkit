package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// Remote applications, delegation and service JWTs.
//
// A remote application is an external issuer controlled by one group. Every
// mutation takes an iam.Actor: registering one needs
// <persona>:credentials:manage in the group; changing or deleting an existing
// one also needs coverage of every role it holds, because whoever controls its
// keys acts as it. Only the system registers applications a group cannot
// change (trust root manual).

// UpsertRemoteApplication registers the issuer app.Issuer in the group ref,
// or updates it there. TrustRoot is the system's to set; other actors
// register at trust root user.
func (a *Client) UpsertRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, app iam.RemoteApplication) (iam.RemoteApplication, error) {
	out, err := a.engine.UpsertRemoteApplication(ctx, actor, ref, app)
	if err != nil {
		return iam.RemoteApplication{}, err
	}
	return *out, nil
}

// DeleteRemoteApplication deletes the application named slug that ref
// controls. Only the system deletes a system-registered application.
func (a *Client) DeleteRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, slug string) error {
	return a.engine.DeleteRemoteApplication(ctx, actor, ref, slug)
}

// RemoteApplication returns the application registered for issuer, disabled
// ones included (Enabled), else ErrRemoteApplicationNotFound.
func (a *Client) RemoteApplication(ctx context.Context, issuer string) (iam.RemoteApplication, error) {
	out, err := a.engine.RemoteApplicationByIssuer(ctx, issuer)
	if err != nil {
		return iam.RemoteApplication{}, err
	}
	return *out, nil
}

// RemoteApplications lists the applications ref controls, newest first.
func (a *Client) RemoteApplications(ctx context.Context, ref iam.GroupRef, page iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error) {
	return a.engine.RemoteApplications(ctx, ref, page)
}

// RemoteApplicationAuthority resolves an application's stored authority: its
// effective permissions and the group they are bound to.
func (a *Client) RemoteApplicationAuthority(ctx context.Context, appID string) (iam.RemoteApplicationAuthority, error) {
	return a.engine.ResolveRemoteApplicationAuthority(ctx, appID)
}

// MintDelegatedAccessToken signs a delegated access token as this deployment.
// A user actor mints only for itself, and every AuthKit permission in
// d.Permissions must be held live by it on the root group
// (iam.ErrDelegationRefused otherwise). The system mints for any subject.
func (a *Client) MintDelegatedAccessToken(ctx context.Context, actor iam.Actor, d iam.DelegatedAccess) (iam.Token, error) {
	return a.engine.MintDelegatedAccessToken(ctx, actor, d)
}

// MintServiceJWT signs a first-party service JWT with this deployment's key.
// It grants nothing AuthKit enforces; the receiver authorizes it.
func (a *Client) MintServiceJWT(ctx context.Context, s iam.ServiceJWT) (iam.Token, iam.ServiceJWTClaims, error) {
	return a.engine.MintServiceJWT(ctx, s)
}
