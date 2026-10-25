import { buttonVariants } from "../ui/button.tsx"
import { useAdmin } from "./context.ts"
import { dateTime } from "./format.ts"
import { useAdminMessages } from "./i18n.ts"
import { useLoad } from "./load.ts"
import { Body, Empty, ErrorText, Loading, NoAccess, Section } from "./parts.tsx"
import { AdminRoot, type AdminProps } from "./root.tsx"
import { BanLine, UserBadges } from "./user-parts.tsx"
import { userName } from "./users-lib.ts"

export interface UserAccountSummaryProps extends Omit<
  AdminProps,
  "basePath" | "guard"
> {
  /** The account's id (OpenRails' customer id). */
  user: string
  /** The account's page in the host, such as `UsersAdmin`'s `basePath/<id>`; through `navigation` when given. */
  href?: string
}

/**
 * One account's standing for another page, such as a billing customer:
 * status, root role, entitlements, ban, last sign-in. Needs
 * `root:users:read`.
 */
export function UserAccountSummary({
  user,
  href,
  ...props
}: UserAccountSummaryProps) {
  return (
    <AdminRoot {...props} basePath="/">
      <Summary id={user} href={href} navigate={props.navigation?.navigate} />
    </AdminRoot>
  )
}

function Summary({
  id,
  href,
  navigate,
}: {
  id: string
  href?: string
  navigate?: (to: string) => void
}) {
  const { t } = useAdminMessages()
  const { client, language } = useAdmin()
  const loaded = useLoad(`user:${id}`, (s) => client.getUser(id, s))
  const title = t("summary.title")
  if (loaded.loading)
    return (
      <Section title={title}>
        <Loading rows={2} />
      </Section>
    )
  const u = loaded.data
  if (!u) {
    const status = loaded.error?.status
    if (status === 403) return <NoAccess />
    if (status === 404)
      return (
        <Section title={title}>
          <Empty>{t("users.notFound")}</Empty>
        </Section>
      )
    return <ErrorText error={loaded.error} onRetry={loaded.reload} />
  }
  return (
    <Section
      title={title}
      description={userName(u)}
      data-slot="user-account-summary"
      actions={
        href && (
          <a
            href={href}
            className={buttonVariants({ variant: "outline", size: "sm" })}
            onClick={(e) => {
              if (!navigate || e.metaKey || e.ctrlKey || e.shiftKey) return
              e.preventDefault()
              navigate(href)
            }}
          >
            {t("summary.open")}
          </a>
        )
      }
    >
      <Body className="gap-3">
        <UserBadges user={u} />
        <BanLine user={u} />
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted-foreground">{t("users.email")}</dt>
          <dd className="truncate">{u.email || u.phone_number || "—"}</dd>
          <dt className="text-muted-foreground">{t("users.lastLogin")}</dt>
          <dd>{dateTime(u.last_login, language) || t("common.never")}</dd>
          <dt className="text-muted-foreground">{t("users.joined")}</dt>
          <dd>{dateTime(u.created_at, language)}</dd>
        </dl>
      </Body>
    </Section>
  )
}
