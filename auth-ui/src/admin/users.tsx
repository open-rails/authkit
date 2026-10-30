import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react"

import type { UserEntry } from "../client/generated/wire.ts"
import { Input } from "../ui/input.tsx"
import { useUsersAccessWith, usersAccess } from "./access.ts"
import type { UserListQuery } from "./client.ts"
import { useAdmin } from "./context.ts"
import { dateTime } from "./format.ts"
import { useAdminMessages } from "./i18n.ts"
import { Link } from "./link.tsx"
import { useLoad } from "./load.ts"
import { Invitations } from "./members.tsx"
import { useCursorPages } from "./pages.ts"
import {
  Body,
  Empty,
  ErrorText,
  FormField,
  Loading,
  NoAccess,
  Pager,
  Section,
  Select,
  Table,
  Td,
  Th,
  ViewTabs,
} from "./parts.tsx"
import { roleTitle } from "./roles-lib.ts"
import { AdminRoot, type AdminProps } from "./root.tsx"
import { useRouter, useSearchParams } from "./router.ts"
import { UserPage } from "./user-page.tsx"
import { UserBadges } from "./user-parts.tsx"
import type { ReviewServiceKeys } from "./offboarding-lib.ts"
import {
  directoryRole,
  entitlementTitle,
  restorableUntil,
  type ConfirmWarnings,
  type UserPanels,
} from "./users-lib.ts"

// On a phone the directory keeps the account and its status; dates are on its page.
const DESKTOP = "hidden sm:table-cell"

export interface UsersAdminProps extends AdminProps {
  /** Canonical tenant group for a matching ForTenant handler at baseUrl.
   * The source authentication session is unchanged. Omit for root/default. */
  tenantId?: string
  /** The host's panels on a user's page (a billing summary, comment standing). */
  userPanels?: UserPanels
  /** Warnings in a ban or delete confirmation; the act still goes ahead. */
  confirmWarnings?: ConfirmWarnings
  /** Entitlements the directory filters by; needs AuthKit's `Deps.EntitlementHolders`. */
  entitlements?: readonly string[]
  /** Language tags, in the canonical form AuthKit stores, the profile editor offers by name; omit for a free-text tag. */
  languages?: readonly string[]
  /** Optional credential inventory after a role loses access; never revokes keys. */
  onReviewServiceKeys?: ReviewServiceKeys
}

export type Host = Pick<
  UsersAdminProps,
  | "userPanels"
  | "confirmWarnings"
  | "entitlements"
  | "languages"
  | "onReviewServiceKeys"
>

/**
 * The user directory and each account's page: search and filters in the
 * URL, ban, delete and restore, profile edits, sessions, sign-in history and
 * the selected directory role and invitations. Views: `basePath` (`?q=`, `?status=`,
 * `?role=`, `?entitlement=`, `?sort=`, `?order=`), `basePath/invitations`,
 * `basePath/<user_id>` (`?kind=`).
 */
export function UsersAdmin({
  userPanels,
  confirmWarnings,
  entitlements,
  languages,
  onReviewServiceKeys,
  ...props
}: UsersAdminProps) {
  return (
    <AdminRoot {...props}>
      <Users
        host={{
          userPanels,
          confirmWarnings,
          entitlements,
          languages,
          onReviewServiceKeys,
        }}
      />
    </AdminRoot>
  )
}

function Users({ host }: { host: Host }) {
  const { t } = useAdminMessages()
  const { client, tenantId } = useAdmin()
  const { segments } = useRouter()
  const group = tenantId ?? "root"
  const root = useUsersAccessWith(client, tenantId)
  const access = useMemo(() => usersAccess(root, tenantId), [root, tenantId])
  const roles = useLoad(root.roles.read ? `roles:${group}` : null, (s) =>
    client.listRoles(group, s)
  )
  if (root.status === "loading")
    return (
      <Section title={t("users.title")}>
        <Loading />
      </Section>
    )
  if (root.status === "error")
    return <ErrorText error={root.error} onRetry={root.reload} />
  if (!access.any) return <NoAccess />
  const roleNames = (roles.data ?? []).map((r) => r.name)
  const [first] = segments
  if (first && first !== "invitations" && access.users.read)
    return (
      <UserPage
        key={JSON.stringify([group, first])}
        id={first}
        access={access}
        roles={roleNames}
        roleCatalog={roles.data ?? []}
        host={host}
      />
    )
  const invitations = first === "invitations" || !access.users.read
  return (
    <>
      {access.users.read && access.users.invite && (
        <ViewTabs
          label={t("users.views")}
          items={[
            { to: "", label: t("users.title"), current: !invitations },
            {
              to: "invitations",
              label: t("invitations.title"),
              current: invitations,
            },
          ]}
        />
      )}
      {invitations ? (
        <Invitations group={group} access={root} roles={roleNames} />
      ) : (
        <Directory roles={roleNames} host={host} />
      )}
    </>
  )
}

const STATUSES = ["active", "banned", "deleted"] as const
type Status = (typeof STATUSES)[number]

// Each order the directory offers, as AuthKit's sort and order.
const SORTS = {
  "created_at:desc": "users.sortNewest",
  "created_at:asc": "users.sortOldest",
  "last_login:desc": "users.sortLastLogin",
  "username:asc": "users.sortUsername",
  "email:asc": "users.sortEmail",
} as const
type SortKey = keyof typeof SORTS
const DEFAULT_SORT: SortKey = "created_at:desc"

const PAGE_SIZE = 25

function Directory({ roles, host }: { roles: string[]; host: Host }) {
  const { t } = useAdminMessages()
  const { client, tenantId } = useAdmin()
  const ids = {
    search: useId(),
    status: useId(),
    role: useId(),
    entitlement: useId(),
    sort: useId(),
  }
  const [search, setSearch] = useSearchParams()
  const q = search.get("q") ?? ""
  const rawStatus = search.get("status") ?? ""
  const status = (STATUSES as readonly string[]).includes(rawStatus)
    ? (rawStatus as Status)
    : ""
  const role = search.get("role") ?? ""
  const entitlement = search.get("entitlement") ?? ""
  const sortKey = `${search.get("sort") ?? "created_at"}:${search.get("order") ?? "desc"}`
  const sort: SortKey = sortKey in SORTS ? (sortKey as SortKey) : DEFAULT_SORT

  const update = (
    changes: Record<string, string | null>,
    options?: { replace?: boolean }
  ) => {
    const next = new URLSearchParams(search)
    for (const [k, v] of Object.entries(changes))
      if (v) next.set(k, v)
      else next.delete(k)
    setSearch(next, options)
  }

  // The search box writes ?q= once typing pauses.
  const [draft, setDraft] = useState({ for: q, text: q })
  const text = draft.for === q ? draft.text : q
  const commit = (value: string) => {
    const next = value.trim()
    if (next === q) return
    setDraft({ for: next, text: value })
    update({ q: next || null }, { replace: true })
  }
  const commitLater = useCallbackRef(commit)
  useEffect(() => {
    if (text.trim() === q) return
    const id = setTimeout(() => commitLater(text), 300)
    return () => clearTimeout(id)
  }, [text, q, commitLater])

  const query = useMemo<UserListQuery>(() => {
    const [by, order] = sort.split(":") as [
      NonNullable<UserListQuery["sort"]>,
      NonNullable<UserListQuery["order"]>,
    ]
    return {
      search: q || undefined,
      status: status || undefined,
      ...(tenantId
        ? { tenantRole: role || undefined }
        : { rootRole: role || undefined }),
      entitlement: entitlement || undefined,
      sort: by,
      order,
      total: true,
      limit: PAGE_SIZE,
    }
  }, [q, status, role, entitlement, sort, tenantId])
  const load = useCallback(
    (cursor: string | undefined, signal?: AbortSignal) =>
      client.listUsers({ ...query, cursor }, signal),
    [client, query]
  )
  const pages = useCursorPages(`users:${JSON.stringify(query)}`, load)
  const filtered = Boolean(q || status || role || entitlement)

  return (
    <Section title={t("users.title")} description={t("users.description")}>
      <Body>
        <form
          role="search"
          className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
          onSubmit={(e) => {
            e.preventDefault()
            commit(text)
          }}
        >
          <div className="sm:col-span-2 lg:col-span-4">
            <FormField label={t("users.search")} htmlFor={ids.search}>
              <Input
                id={ids.search}
                type="search"
                autoComplete="off"
                placeholder={t("users.searchPlaceholder")}
                value={text}
                onChange={(e) => setDraft({ for: q, text: e.target.value })}
              />
            </FormField>
          </div>
          <FormField label={t("users.status")} htmlFor={ids.status}>
            <Select
              id={ids.status}
              value={status}
              onChange={(e) => update({ status: e.target.value || null })}
            >
              <option value="">{t("users.statusLive")}</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {t(`users.${s}`)}
                </option>
              ))}
            </Select>
          </FormField>
          {roles.length > 0 && (
            <FormField
              label={t(tenantId ? "users.tenantRoleTitle" : "users.role")}
              htmlFor={ids.role}
            >
              <Select
                id={ids.role}
                value={role}
                onChange={(e) => update({ role: e.target.value || null })}
              >
                <option value="">{t("users.anyRole")}</option>
                {roles.map((r) => (
                  <option key={r} value={r}>
                    {roleTitle(r)}
                  </option>
                ))}
              </Select>
            </FormField>
          )}
          {host.entitlements && host.entitlements.length > 0 && (
            <FormField label={t("users.entitlement")} htmlFor={ids.entitlement}>
              <Select
                id={ids.entitlement}
                value={entitlement}
                onChange={(e) =>
                  update({ entitlement: e.target.value || null })
                }
              >
                <option value="">{t("users.anyEntitlement")}</option>
                {host.entitlements.map((e) => (
                  <option key={e} value={e}>
                    {entitlementTitle(e)}
                  </option>
                ))}
              </Select>
            </FormField>
          )}
          <FormField label={t("users.sort")} htmlFor={ids.sort}>
            <Select
              id={ids.sort}
              value={sort}
              onChange={(e) => {
                const [by, order] = e.target.value.split(":")
                const plain = e.target.value === DEFAULT_SORT
                update({ sort: plain ? null : by, order: plain ? null : order })
              }}
            >
              {(Object.keys(SORTS) as SortKey[]).map((k) => (
                <option key={k} value={k}>
                  {t(SORTS[k])}
                </option>
              ))}
            </Select>
          </FormField>
        </form>
      </Body>
      {pages.loading ? (
        <Loading rows={5} />
      ) : pages.error && !pages.items ? (
        <Body>
          <ErrorText error={pages.error} onRetry={pages.reload} />
        </Body>
      ) : !pages.items?.length && pages.page === 1 ? (
        <Empty>{filtered ? t("users.emptyFiltered") : t("users.empty")}</Empty>
      ) : (
        <>
          <UserTable users={pages.items ?? []} status={status} />
          <Pager
            page={pages.page}
            summary={
              pages.total !== null && t("users.total", { count: pages.total })
            }
            onPrevious={pages.previous}
            onNext={pages.next}
          />
        </>
      )}
    </Section>
  )
}

function UserTable({ users, status }: { users: UserEntry[]; status: string }) {
  const { t } = useAdminMessages()
  const { tenantId, language } = useAdmin()
  return (
    <Table aria-label={t("users.title")}>
      <thead>
        <tr>
          <Th>{t("users.user")}</Th>
          <Th>{t("users.status")}</Th>
          {status === "banned" ? (
            <>
              <Th className={DESKTOP}>{t("users.until")}</Th>
              <Th className={DESKTOP}>{t("users.reason")}</Th>
            </>
          ) : status === "deleted" ? (
            <>
              <Th className={DESKTOP}>{t("users.deletedAt")}</Th>
              <Th className={DESKTOP}>{t("users.restorableUntil")}</Th>
            </>
          ) : (
            <>
              <Th className={DESKTOP}>{t("users.joined")}</Th>
              <Th className={DESKTOP}>{t("users.lastLogin")}</Th>
            </>
          )}
        </tr>
      </thead>
      <tbody>
        {users.map((u) => (
          <tr key={u.id}>
            <Td className="max-w-72">
              <div className="grid min-w-0">
                <Link
                  to={u.id}
                  className={
                    u.deleted_at
                      ? "truncate font-medium text-muted-foreground line-through hover:underline"
                      : "truncate font-medium hover:underline"
                  }
                >
                  {u.username || u.id}
                </Link>
                <span className="truncate text-xs text-muted-foreground">
                  {u.email || u.phone_number || "—"}
                </span>
              </div>
            </Td>
            <Td>
              <UserBadges user={u} role={directoryRole(u, tenantId)} />
            </Td>
            {status === "banned" ? (
              <>
                <Td className={`whitespace-nowrap ${DESKTOP}`}>
                  {u.ban?.until
                    ? dateTime(u.ban.until, language)
                    : t("users.permanent")}
                </Td>
                <Td
                  className={`max-w-80 truncate ${DESKTOP}`}
                  title={u.ban?.reason ?? ""}
                >
                  {u.ban?.reason || "—"}
                </Td>
              </>
            ) : status === "deleted" ? (
              <>
                <Td className={`whitespace-nowrap ${DESKTOP}`}>
                  {dateTime(u.deleted_at, language)}
                </Td>
                <Td className={`whitespace-nowrap ${DESKTOP}`}>
                  {u.deleted_at
                    ? dateTime(restorableUntil(u.deleted_at), language)
                    : ""}
                </Td>
              </>
            ) : (
              <>
                <Td className={`whitespace-nowrap ${DESKTOP}`}>
                  {dateTime(u.created_at, language)}
                </Td>
                <Td className={`whitespace-nowrap ${DESKTOP}`}>
                  {dateTime(u.last_login, language) || t("common.never")}
                </Td>
              </>
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  )
}

// A stable function that always calls the latest fn.
function useCallbackRef<A extends unknown[]>(fn: (...args: A) => void) {
  const ref = useRef(fn)
  useEffect(() => {
    ref.current = fn
  })
  return useCallback((...args: A) => ref.current(...args), [])
}
