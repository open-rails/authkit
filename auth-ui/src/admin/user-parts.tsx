import type { UserEntry } from "../client/generated/wire.ts"
import { Badge } from "../ui/badge.tsx"
import { useAdmin } from "./context.ts"
import { dateTime } from "./format.ts"
import { useAdminMessages } from "./i18n.ts"
import { roleTitle } from "./roles-lib.ts"
import { entitlementTitle, userState } from "./users-lib.ts"

export function StatusBadge({ user }: { user: UserEntry }) {
  const { t } = useAdminMessages()
  const state = userState(user)
  return state === "active" ? (
    <Badge variant="outline" className="border-success/40 text-success">
      {t("users.active")}
    </Badge>
  ) : (
    <Badge variant="destructive">{t(`users.${state}`)}</Badge>
  )
}

// Status, selected directory role (root by default) and entitlements.
export function UserBadges({
  user,
  role = user.root_role,
}: {
  user: UserEntry
  role?: string | null
}) {
  return (
    <span className="flex flex-wrap items-center gap-1">
      <StatusBadge user={user} />
      {role && (
        <Badge variant="secondary" title={role}>
          {roleTitle(role)}
        </Badge>
      )}
      {user.entitlements.map((e) => (
        <Badge key={e} variant="outline" title={e}>
          {entitlementTitle(e)}
        </Badge>
      ))}
    </span>
  )
}

// The ban in force, or the last one that ran out.
export function BanLine({ user }: { user: UserEntry }) {
  const { t } = useAdminMessages()
  const { language } = useAdmin()
  const ban = user.ban ?? user.expired_ban
  if (!ban) return null
  const text = user.ban
    ? ban.until
      ? t("users.bannedUntil", { date: dateTime(ban.until, language) })
      : t("users.bannedForever")
    : t("users.banEnded", { date: dateTime(ban.until, language) })
  return (
    <p
      className={
        user.ban ? "text-sm text-destructive" : "text-sm text-muted-foreground"
      }
    >
      {text}
      {ban.reason && (
        <>
          {" · "}
          <span>{ban.reason}</span>
        </>
      )}
    </p>
  )
}
