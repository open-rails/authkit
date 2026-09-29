package embedded

import (
	"github.com/open-rails/authkit/iam"
)

// ErrRenameRateLimited is returned when a username rename is attempted before
// the configured rename interval has elapsed.
var ErrRenameRateLimited = iam.ErrRenameRateLimited

// ErrOwnerSlugTaken is retained as a stable sentinel for identity-policy error
// mapping. Under the permission-group model usernames are unique on their own
// (the owner-slug reservation plane was removed); kept so dependents' errors.Is
// checks keep compiling.
var ErrOwnerSlugTaken = iam.ErrOwnerSlugTaken

// NamingPolicy returns the normalized site policy for users and groups.
func (s *engine) NamingPolicy() iam.NamingPolicy { return s.cfg.namingPolicy }
