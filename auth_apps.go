package authkit

import (
	"context"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/jwtkit"
)

// Remote applications, delegation, service JWTs and published documents.
//
// A remote application is an external issuer controlled by one group. Every
// mutation takes an iam.Actor: registering one needs
// <persona>:credentials:manage in the group; changing or deleting an existing
// one also needs coverage of every role it holds, because whoever controls its
// keys acts as it. Only the system registers applications that are approved
// or not rotated by a group (trust root manual), and only a domain proof
// rotates a domain-rooted one.

// UpsertRemoteApplication registers the issuer app.Issuer in the group ref,
// or updates it there. Tier and TrustRoot are the system's to set; other
// actors register at tier registered, trust root user.
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
// Published documents are stamped into every token.
func (a *Client) MintDelegatedAccessToken(ctx context.Context, actor iam.Actor, d iam.DelegatedAccess) (iam.Token, error) {
	return a.engine.MintDelegatedAccessToken(ctx, actor, d)
}

// MintRemoteApplicationAccessToken signs a remote-application access token
// with this deployment's key: this deployment acting as an application
// registered with another verifier.
func (a *Client) MintRemoteApplicationAccessToken(ctx context.Context, p iam.RemoteApplicationAccess) (iam.Token, error) {
	return a.engine.MintRemoteApplicationAccessToken(ctx, p)
}

// MintServiceJWT signs a first-party service JWT with this deployment's key.
// It grants nothing AuthKit enforces; the receiver authorizes it.
func (a *Client) MintServiceJWT(ctx context.Context, s iam.ServiceJWT) (iam.Token, iam.ServiceJWTClaims, error) {
	return a.engine.MintServiceJWT(ctx, s)
}

// PublishDocument signs an application document with this deployment's key
// and stores it. From then on AuthKit serves it at iam.DocumentsPath beneath
// HTTPConfig.BasePath to Config.Documents.Readers and stamps its reference
// into every delegated token it mints. Each type is published once per
// process; it needs Config.Documents.Readers.
func (a *Client) PublishDocument(ctx context.Context, p documents.Publication) (documents.Reference, error) {
	return a.engine.PublishDocument(ctx, p)
}

// MintServiceJWT signs a service JWT with an explicit signer and issuer, for
// hosts that manage the signing key outside AuthKit.
func MintServiceJWT(ctx context.Context, signer jwtkit.Signer, issuer string, s iam.ServiceJWT) (iam.Token, iam.ServiceJWTClaims, error) {
	return engine.MintServiceJWT(ctx, signer, issuer, s)
}

// MintRemoteApplicationAccessToken signs a remote-application access token
// with an explicit signer; p.Issuer is required.
func MintRemoteApplicationAccessToken(ctx context.Context, signer jwtkit.Signer, p iam.RemoteApplicationAccess) (iam.Token, error) {
	return engine.MintRemoteApplicationAccessToken(ctx, signer, p)
}
