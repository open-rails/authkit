package authkit

import (
	"context"
	"time"
)

// Small capability interfaces — narrow slices of Client (#143). A host's
// authorization or token-minting layer should depend on the slice it actually
// uses, not the full 94-method Client. Both embedded.Client and (Phase 2)
// remote.Client satisfy these; the broad Client interface remains the swap seam.
//
// These are grown from REAL consumption points, not a speculative taxonomy — add
// a new one only when a real function signature narrows to it.

// Authorizer is the "can this subject do X here" slice: permission checks, the
// live-user/ban gate, and role resolution. doujins's request gate depends on this.
type Authorizer interface {
	Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error)
	ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error)
	IsUserAllowed(ctx context.Context, userID string) (bool, error)
	ListRoleSlugsByUserErr(ctx context.Context, userID string) ([]string, error)
}

// TokenIssuer is the token-minting slice: service JWTs, delegated access tokens,
// custom and remote-application tokens. openrails/tensorhub platform minting
// depends on this.
type TokenIssuer interface {
	IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (string, time.Time, error)
	MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error)
	MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error)
	MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error)
	MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error)
}
