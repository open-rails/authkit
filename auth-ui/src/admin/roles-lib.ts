import type { GroupRole } from "../client/generated/wire.ts"
import type { AdminMessageKey } from "./i18n.ts"

// A role as people read it: a custom role's own name, a declared one's
// capitalized.
export function roleTitle(role: string): string {
  const name = role.slice(role.indexOf(":") + 1)
  if (name.startsWith("custom-")) return name.slice("custom-".length)
  return name.charAt(0).toUpperCase() + name.slice(1)
}

export const ownerRole = (persona: string) => `${persona}:owner`

/** What a permission opens, for the role editor (OpenRails passes `billingPermissionHelp`). */
export type PermissionHelpEntry =
  string | { label: string; description?: string; section?: string }

/** By permission (`merchant:billing:read`) or by resource and action (`billing:read`). */
export type PermissionHelp = Record<string, PermissionHelpEntry>

// AuthKit's own permissions, the same on every persona.
const BUILT_IN: Record<string, AdminMessageKey> = {
  "members:read": "roles.perms.membersRead",
  "members:manage": "roles.perms.membersManage",
  "credentials:read": "roles.perms.credentialsRead",
  "credentials:manage": "roles.perms.credentialsManage",
  "roles:read": "roles.perms.rolesRead",
  "roles:manage": "roles.perms.rolesManage",
  "directory:read": "roles.perms.directoryRead",
  "directory:manage": "roles.perms.directoryManage",
  "users:read": "roles.perms.usersRead",
  "users:ban": "roles.perms.usersBan",
  "users:delete": "roles.perms.usersDelete",
  "users:manage": "roles.perms.usersManage",
  "users:invite": "roles.perms.usersInvite",
}

export type Described = {
  label: string
  description?: string
  section: string
  builtIn: boolean
}

const rest = (perm: string) => perm.slice(perm.indexOf(":") + 1)

export function describePermission(
  perm: string,
  help: PermissionHelp | undefined,
  t: (key: AdminMessageKey) => string
): Described {
  const entry = help?.[perm] ?? help?.[rest(perm)]
  const builtIn = BUILT_IN[rest(perm)]
  if (entry)
    return typeof entry === "string"
      ? { label: entry, section: "", builtIn: false }
      : {
          label: entry.label,
          description: entry.description,
          section: entry.section ?? "",
          builtIn: false,
        }
  if (builtIn) return { label: t(builtIn), section: "", builtIn: true }
  return { label: rest(perm), section: "", builtIn: false }
}

// Every permission a role of the group may hold: what its owner covers.
export function catalogOf(roles: GroupRole[], persona: string): string[] {
  const owner = roles.find((r) => r.name === ownerRole(persona))
  const perms = owner ? owner.permissions : roles.flatMap((r) => r.permissions)
  return [...new Set(perms)].sort()
}

// A custom role's bare name.
export const ROLE_NAME = /^[a-z][a-z0-9-]{0,63}$/
