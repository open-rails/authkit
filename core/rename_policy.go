package core

import "time"

// renameCooldown is how long a user or tenant must wait between consecutive
// renames. Hardcoded — not a configurable Options field — so the policy
// is uniform across deployments and support workflows are predictable.
//
// Same value for both kinds: a personal-tenant rename always rides the
// user-rename intent (one transaction), so the cooldown only ever
// gates one "intent per row per cooldown window." Non-personal tenants
// have their own independent cooldown via `tenant_renames.renamed_at`.
//
// Admins can bypass via `RenameTenantSlugForce` / `RenameUsernameForce`
// for support cases (typo correction, deadname requests, etc.).
const renameCooldown = 72 * time.Hour

// renameReuseHold is how long a renamed-away slug remains unavailable for
// registration by another user/tenant. Redirect/history lookup remains backed by
// the rename rows indefinitely; this value only controls reuse blocking.
const renameReuseHold = 90 * 24 * time.Hour
