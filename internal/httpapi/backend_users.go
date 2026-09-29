package httpapi

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// usersBackend is the account directory and account administration.
type usersBackend interface {
	AdminGetUser(ctx context.Context, id string) (*iam.AdminUser, error)
	AdminListUsers(ctx context.Context, opts iam.AdminUserListOptions) (*iam.AdminListUsersResult, error)
	BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error
	GetUserByEmail(ctx context.Context, email string) (*iam.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*iam.User, error)
	PublicUsersByIDs(ctx context.Context, ids []string) (map[string]iam.PublicUserRef, error)
	UpdateUsername(ctx context.Context, id, username string) error
	UnbanUserAs(ctx context.Context, actorUserID, userID string) error
	GetPreferredLanguage(ctx context.Context, userID string) (authflow.PreferredLanguage, error)
	SetPreferredLanguage(ctx context.Context, userID, language string) error
	SoftDeleteUser(ctx context.Context, id string) error
	SoftDeleteUserAs(ctx context.Context, actorUserID, userID string) error
	RestoreUserAs(ctx context.Context, actorUserID, userID string) error
	UserNamingState(ctx context.Context, id string) (iam.NamingState, error)
	UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error)
}
