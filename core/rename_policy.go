package core

import (
	"errors"
	"time"
)

// renameCooldown is how long a user must wait between consecutive username
// renames. Hardcoded — not a configurable Options field — so the policy is
// uniform across deployments and support workflows are predictable. Admins can
// bypass via UpdateUsernameForce for support cases (typo correction, deadname
// requests, etc.).
const renameCooldown = 72 * time.Hour

// ErrRenameRateLimited is returned when a username rename is attempted before
// the renameCooldown window has elapsed.
var ErrRenameRateLimited = errors.New("rename_rate_limited")

// ErrOwnerSlugTaken is retained as a stable sentinel for identity-policy error
// mapping. Under the permission-group model usernames are unique on their own
// (the org-slug reservation plane was removed); kept so dependents' errors.Is
// checks keep compiling.
var ErrOwnerSlugTaken = errors.New("owner_slug_taken")
