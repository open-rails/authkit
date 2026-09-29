package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// usersBackend is the account directory and account administration.
type usersBackend interface {
	User(ctx context.Context, ref iam.UserRef, opts ...iam.ReadOption) (iam.User, error)
	ListUsers(ctx context.Context, q iam.UserQuery) (iam.ListPage[iam.User], error)
	UserDirectoryDetails(ctx context.Context, ids []string) map[string]authflow.UserDirectoryDetail
	UpdateUser(ctx context.Context, a iam.Actor, userID string, u iam.UserUpdate) (iam.User, error)
	Ban(ctx context.Context, a iam.Actor, userID string, b iam.Ban) error
	Unban(ctx context.Context, a iam.Actor, userID string) error
	DeleteUsers(ctx context.Context, a iam.Actor, ids []string) ([]iam.OpResult, error)
	RestoreUsers(ctx context.Context, a iam.Actor, ids []string) ([]iam.OpResult, error)
	UserNamingState(ctx context.Context, id string) (iam.NamingState, error)
	HasUsableMFA(ctx context.Context, userID string) (bool, error)
	UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error)
}
