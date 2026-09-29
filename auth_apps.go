package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Remote applications, service JWTs and delegation.

func (a *Auth) MintRemoteApplicationAccessToken(ctx context.Context, p iam.RemoteApplicationAccessParams) (string, error) {
	return a.engine.MintRemoteApplicationAccessToken(ctx, p)
}

func (a *Auth) MintServiceJWT(ctx context.Context, opts iam.ServiceJWTMintOptions) (string, iam.ServiceJWTClaims, error) {
	return a.engine.MintServiceJWT(ctx, opts)
}

func (a *Auth) UpsertRemoteApplication(ctx context.Context, in iam.RemoteApplication) (*iam.RemoteApplication, error) {
	return a.engine.UpsertRemoteApplication(ctx, in)
}

func (a *Auth) GetRemoteApplication(ctx context.Context, issuer string) (*iam.RemoteApplication, error) {
	return a.engine.GetRemoteApplication(ctx, issuer)
}

func (a *Auth) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (iam.RemoteApplicationAuthority, error) {
	return a.engine.ResolveRemoteApplicationAuthority(ctx, appID)
}

// MintDelegatedAccessToken signs a delegated access token with this
// deployment's signer. An empty p.Issuer defaults to the configured issuer.
func (a *Auth) MintDelegatedAccessToken(ctx context.Context, p iam.DelegatedAccessParams) (string, error) {
	return a.engine.MintDelegatedAccessToken(ctx, p)
}

// DelegatedPermissionLive re-checks a delegated token this deployment minted
// against its subject's live authority; it makes Auth a
// verify.DelegatedAuthority for verify.RequirePermission.
func (a *Auth) DelegatedPermissionLive(ctx context.Context, cl verify.Claims, perm iam.Perm) (bool, error) {
	return a.engine.DelegatedPermissionLive(ctx, cl, perm)
}
