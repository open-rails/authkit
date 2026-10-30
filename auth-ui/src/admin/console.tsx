import { useMemo } from "react"

import { cn } from "cn"
import { useAccessWith, useUsersAccessWith, usersAccess } from "./access.ts"
import { ApiKeysAdmin } from "./api-keys.tsx"
import { useAdmin } from "./context.ts"
import { useAdminMessages } from "./i18n.ts"
import { MembersAdmin } from "./members.tsx"
import { OAuthClientsAdmin } from "./oauth-clients.tsx"
import { ErrorText, Loading, NoAccess, ViewTabs } from "./parts.tsx"
import {
  RemoteApplicationsAdmin,
  type RemoteApplicationsAdminProps,
} from "./remote-applications.tsx"
import { RolesAdmin, type RolesAdminProps } from "./roles.tsx"
import { AdminRoot, type AdminProps } from "./root.tsx"
import { useRouter } from "./router.ts"
import { UsersAdmin, type UsersAdminProps } from "./users.tsx"

const SECTIONS = [
  "users",
  "members",
  "roles",
  "api-keys",
  "oauth-clients",
  "remote-applications",
] as const

export type AuthAdminSection = (typeof SECTIONS)[number]

/** Optional reference console over the independently usable admin panels. */
export interface AuthAdminProps extends AdminProps {
  /** The host-controlled group for group administration. Default `root`. */
  group?: string
  /** Sections enabled by this host's AuthKit configuration; all by default. */
  sections?: readonly AuthAdminSection[]
  /** The account directory (root/default or a tenant) stays separate from the selected group. */
  users?:
    | false
    | Pick<
        UsersAdminProps,
        | "tenantId"
        | "userPanels"
        | "confirmWarnings"
        | "entitlements"
        | "onReviewServiceKeys"
      >
  permissionHelp?: RolesAdminProps["permissionHelp"]
  remoteApplications?: Pick<
    RemoteApplicationsAdminProps,
    "scope" | "tokenEndpoint"
  >
}

/**
 * A routed, embeddable AuthKit console. It mounts only the selected permitted
 * panel. The host supplies the group and authentication; this creates no server
 * or privileges. Key it by the signed-in account id when that account changes.
 */
export function AuthAdmin({
  group = "root",
  sections = SECTIONS,
  users,
  permissionHelp,
  remoteApplications,
  className,
  ...props
}: AuthAdminProps) {
  return (
    <AdminRoot {...props} tenantId={users ? users.tenantId : undefined}>
      <Console
        key={JSON.stringify([
          group,
          props.baseUrl,
          props.basePath,
          users && users.tenantId,
        ])}
        shared={props}
        group={group}
        sections={sections}
        users={users}
        permissionHelp={permissionHelp}
        remoteApplications={remoteApplications}
        className={className}
      />
    </AdminRoot>
  )
}

function Console({
  shared,
  group,
  sections,
  users,
  permissionHelp,
  remoteApplications,
  className,
}: Omit<AuthAdminProps, keyof AdminProps | "group"> & {
  shared: AdminProps
  group: string
  sections: readonly AuthAdminSection[]
  className?: string
}) {
  const { client } = useAdmin()
  const { t } = useAdminMessages()
  const router = useRouter()
  const root = useUsersAccessWith(client, users ? users.tenantId : undefined)
  const scoped = useAccessWith(client, group)
  const accounts = useMemo(
    () => usersAccess(root, users ? users.tenantId : undefined),
    [root, users]
  )
  const enabled = new Set(sections)
  const permitted = {
    users: users !== false && accounts.any,
    members: scoped.members.read || scoped.invite,
    roles: scoped.roles.read,
    "api-keys": scoped.credentials.read,
    "oauth-clients": scoped.credentials.read,
    "remote-applications": scoped.credentials.read,
  }
  const available = SECTIONS.filter(
    (section) => enabled.has(section) && permitted[section]
  )
  const requested = router.segments[0]
  const selected = requested ?? available[0]
  const checking =
    (enabled.has("users") && users !== false && root.status === "loading") ||
    (SECTIONS.some((section) => section !== "users" && enabled.has(section)) &&
      scoped.status === "loading")
  const labels = {
    users: t("users.title"),
    members: t("members.title"),
    roles: t("roles.title"),
    "api-keys": t("apiKeys.title"),
    "oauth-clients": t("oauthClients.title"),
    "remote-applications": t("remoteApps.title"),
  }
  const retry = () => {
    root.reload()
    scoped.reload()
  }
  const error =
    selected === "users"
      ? root.error
      : selected
        ? scoped.error
        : ((enabled.has("users") && users !== false ? root.error : null) ??
          scoped.error)

  const panel = () => {
    if (checking) return <Loading />
    if (!selected || !available.includes(selected as AuthAdminSection)) {
      if (error) return <ErrorText error={error} onRetry={retry} />
      return <NoAccess />
    }
    const props = { ...shared, basePath: router.href(selected) }
    const reviewServiceKeys =
      enabled.has("api-keys") && scoped.credentials.read
        ? () => router.navigate("api-keys")
        : undefined
    switch (selected) {
      case "users":
        return (
          <UsersAdmin
            {...props}
            {...(users || {})}
            onReviewServiceKeys={
              (users || {}).onReviewServiceKeys ??
              (((users && users.tenantId) || "root") === group
                ? reviewServiceKeys
                : undefined)
            }
          />
        )
      case "members":
        return (
          <MembersAdmin
            {...props}
            group={group}
            onReviewServiceKeys={reviewServiceKeys}
          />
        )
      case "roles":
        return (
          <RolesAdmin
            {...props}
            group={group}
            permissionHelp={permissionHelp}
          />
        )
      case "api-keys":
        return <ApiKeysAdmin {...props} group={group} />
      case "oauth-clients":
        return <OAuthClientsAdmin {...props} group={group} />
      case "remote-applications":
        return (
          <RemoteApplicationsAdmin
            {...props}
            group={group}
            {...remoteApplications}
          />
        )
      default:
        return <NoAccess />
    }
  }

  return (
    <section className={cn("grid gap-6", className)}>
      <h1 className="text-2xl font-semibold tracking-tight">
        {t("console.title")}
      </h1>
      {!checking && available.length > 0 && (
        <div className="[&>nav]:flex-wrap">
          <ViewTabs
            label={t("console.title")}
            items={available.map((section) => ({
              to: section,
              label: labels[section],
              current: section === selected,
            }))}
          />
        </div>
      )}
      <div data-auth-admin-view={selected}>{panel()}</div>
    </section>
  )
}
