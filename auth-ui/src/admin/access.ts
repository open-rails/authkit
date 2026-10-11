import { useMemo } from "react"

import type { AuthKitError } from "../client/errors.ts"
import type { PermissionSet } from "../client/generated/wire.ts"
import {
  createAdminClient,
  type AdminAuth,
  type AdminClient,
} from "./client.ts"
import { useLoad } from "./load.ts"

/** What the signed-in person may do in one group, from `GET /me/permissions`. */
export type GroupAdminAccess = {
  status: "loading" | "ready" | "error"
  error: AuthKitError | null
  /** The group's persona (`merchant`, `root`); null while unknown. */
  persona: string | null
  /** The role held there, if any (root staff act through their root role). */
  role: string | null
  permissions: ReadonlySet<string>
  members: { read: boolean; manage: boolean }
  /** Invite: `members:manage`, or `root:users:invite` on root. */
  invite: boolean
  /** The role list reads with `members:read` or `roles:read`. */
  roles: { read: boolean; manage: boolean }
  credentials: { read: boolean; manage: boolean }
  /** Any of the above. */
  any: boolean
  reload(): void
}

export function groupAccess(
  group: string,
  set: PermissionSet | undefined
): Omit<GroupAdminAccess, "status" | "error" | "reload"> {
  const permissions = new Set(set?.permissions ?? [])
  const persona =
    set?.role?.split(":")[0] ??
    set?.permissions[0]?.split(":")[0] ??
    (group === "root" ? "root" : null)
  const holds = (perm: string) =>
    persona !== null && permissions.has(`${persona}:${perm}`)
  const members = {
    read: holds("members:read"),
    manage: holds("members:manage"),
  }
  const roles = {
    read: holds("roles:read") || members.read,
    manage: holds("roles:manage"),
  }
  const credentials = {
    read: holds("credentials:read"),
    manage: holds("credentials:manage"),
  }
  const invite =
    members.manage ||
    (persona === "root" && permissions.has("root:users:invite"))
  return {
    persona,
    role: set?.role ?? null,
    permissions,
    members,
    invite,
    roles,
    credentials,
    any: members.read || roles.read || credentials.read || invite,
  }
}

export function useAccessWith(
  client: AdminClient,
  group: string
): GroupAdminAccess {
  const loaded = useLoad(`access:${group}`, (signal) =>
    client.permissions(group, signal)
  )
  return useMemo(
    () => ({
      ...groupAccess(group, loaded.data),
      status: loaded.data ? "ready" : loaded.error ? "error" : "loading",
      error: loaded.error,
      reload: loaded.reload,
    }),
    [group, loaded.data, loaded.error, loaded.reload]
  )
}

/**
 * The signed-in person's access in group, for a host hiding the tabs of
 * the admin components it would show nothing in (`any`).
 */
export function useGroupAdminAccess(options: {
  auth: AdminAuth
  baseUrl?: string
  group: string
}): GroupAdminAccess {
  const { auth, baseUrl, group } = options
  const client = useMemo(
    () => createAdminClient({ auth, baseUrl }),
    [auth, baseUrl]
  )
  return useAccessWith(client, group)
}
