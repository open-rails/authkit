package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/naming"
)

// usersBackend is the admin account view and the caller's own account view.
type usersBackend interface {
	UserEntry(ctx context.Context, userID string) (iam.UserEntry, error)
	UserNamingState(ctx context.Context, id string) (naming.State, error)
	HasUsableMFA(ctx context.Context, userID string) (bool, error)
	UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error)
	UserSecurity(ctx context.Context, in authflow.ProfileInput) (authflow.UserSecurity, error)
	Agreements() []iam.Agreement
	RecordAgreements(ctx context.Context, userID string, refs []iam.AgreementRef, channel iam.AgreementChannel, ip, userAgent string) error
}
