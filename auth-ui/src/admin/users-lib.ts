import type { ReactNode } from "react"

import type { UserEntry } from "../client/generated/wire.ts"

/** The acts a host may warn about before they happen. */
export type UserAction = "ban" | "delete"

/**
 * Warnings shown in a ban or delete confirmation, such as an active
 * subscription that keeps running. An array is one warning per item; a
 * promise is awaited while the confirmation waits. The act still goes ahead.
 */
export type ConfirmWarnings = (
  user: UserEntry,
  action: UserAction
) => ReactNode | Promise<ReactNode>

/** A user page's panels from the host, after AuthKit's own. */
export type UserPanels = (user: UserEntry) => ReactNode

/** The role in the selected directory; global root roles stay separate. */
export const directoryRole = (
  user: UserEntry,
  tenantId?: string
): string | null => {
  if (!tenantId) return user.root_role
  return "tenant_role" in user && typeof user.tenant_role === "string"
    ? user.tenant_role
    : null
}

export const userName = (u: UserEntry) => u.username || u.email || u.id

export type UserState = "active" | "banned" | "deleted"

export const userState = (u: UserEntry): UserState =>
  u.deleted_at ? "deleted" : u.ban ? "banned" : "active"

// Deletion keeps an account restorable this long.
const RECOVERY_DAYS = 30

export const restorableUntil = (deletedAt: string) =>
  new Date(Date.parse(deletedAt) + RECOVERY_DAYS * 86_400_000).toISOString()
