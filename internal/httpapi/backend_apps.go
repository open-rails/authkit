package httpapi

import (
	"context"
	"time"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// appsBackend is remote applications, delegation, DPoP and published documents.
type appsBackend interface {
	ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error)
	DelegationAuthorizer() iam.DelegationAuthorizer
	UpsertRemoteApplication(ctx context.Context, a iam.Actor, ref iam.GroupRef, in iam.RemoteApplication) (*iam.RemoteApplication, error)
	DeleteRemoteApplication(ctx context.Context, a iam.Actor, ref iam.GroupRef, slug string) error
	GetRemoteApplicationBySlug(ctx context.Context, slug string) (*iam.RemoteApplication, error)
	RemoteApplications(ctx context.Context, ref iam.GroupRef, page iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error)
	MintDelegatedAccessToken(ctx context.Context, a iam.Actor, d iam.DelegatedAccess) (iam.Token, error)
	RegisterApplicationFromDomain(ctx context.Context, domain string) (*authflow.RegisteredApplication, error)
	LookupDocument(ctx context.Context, digest string) (documents.SignedDocument, error)
}
