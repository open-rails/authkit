import type { GroupRole } from "../client/generated/wire.ts"

/** The host opens its credential inventory; this is not evidence of possession. */
export type ReviewServiceKeys = (context: {
  group: string
  userId: string
}) => void

// Compare concrete grants, not role names: hosts define their own hierarchy.
// An unavailable catalog cannot establish that a change is a promotion.
export function losesRoleAccess(
  current: string | null | undefined,
  next: string | null | undefined,
  roles: readonly GroupRole[]
): boolean {
  if (!current || current === next) return false
  if (!next) return true
  const before = roles.find((role) => role.name === current)
  const after = roles.find((role) => role.name === next)
  if (!before || !after) return true
  const retained = new Set(after.permissions)
  return before.permissions.some((permission) => !retained.has(permission))
}
