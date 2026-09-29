package httpapi

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// appsBackend is remote applications, delegation and DPoP.
type appsBackend interface {
	CheckDelegatedGrant(ctx context.Context, userID string, permissions []string) error
	ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error)
	DelegationAuthorizer() iam.DelegationAuthorizer
	DeleteRemoteApplication(ctx context.Context, issuer string) error
	DeleteRemoteApplicationForActor(ctx context.Context, a iam.Actor, group iam.GroupRef, slug string) error
	UpsertRemoteApplicationForActor(ctx context.Context, a iam.Actor, group iam.GroupRef, in iam.RemoteApplication) (*iam.RemoteApplication, error)
	GetRemoteApplicationBySlug(ctx context.Context, slug string) (*iam.RemoteApplication, error)
	ListRemoteApplicationsForGroup(ctx context.Context, group iam.GroupRef) ([]iam.RemoteApplication, error)
	MintDelegatedAccessToken(ctx context.Context, p iam.DelegatedAccessParams) (string, error)
	RegisterApplicationFromDomain(ctx context.Context, domain string) (*authflow.RegisteredApplication, error)
}
