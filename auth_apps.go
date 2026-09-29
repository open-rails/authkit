package authkit

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/jwtkit"
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

// ClaimDPoPProof atomically claims a DPoP proof key until ttl elapses in
// AuthKit's shared store: the replay guard for verify.WithDPoP on a host's
// resource server.
func (a *Auth) ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return a.engine.ClaimDPoPProof(ctx, key, ttl)
}

// MintServiceJWT signs a service JWT with an explicit signer and issuer, for
// hosts that manage the signing key outside AuthKit. It defaults to a
// 15-minute lifetime, stamps token_use=service and grants no host permission
// by itself.
func MintServiceJWT(ctx context.Context, signer jwtkit.Signer, issuer string, opts iam.ServiceJWTMintOptions) (string, iam.ServiceJWTClaims, error) {
	return engine.MintServiceJWT(ctx, signer, issuer, opts)
}

// MintRemoteApplicationAccessToken signs a remote application access token
// with an explicit signer. Identity is the validated iss; authority is
// stored and resolved at verification. A non-nil p.Permissions only narrows
// that stored ceiling.
func MintRemoteApplicationAccessToken(ctx context.Context, signer jwtkit.Signer, p iam.RemoteApplicationAccessParams) (string, error) {
	return engine.MintRemoteApplicationAccessToken(ctx, signer, p)
}
