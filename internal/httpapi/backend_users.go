package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// usersBackend is the admin account view and the caller's own account view.
type usersBackend interface {
	UserEntry(ctx context.Context, userID string) (iam.UserEntry, error)
	UserNamingState(ctx context.Context, id string) (iam.NamingState, error)
	HasUsableMFA(ctx context.Context, userID string) (bool, error)
	UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error)
}
