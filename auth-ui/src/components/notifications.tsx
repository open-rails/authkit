import { Popover } from "@base-ui/react/popover"
import { Notification01Icon, RefreshIcon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { cn } from "cn"
import { useEffect, useId, useRef, useState, type ReactNode } from "react"
import type { NotificationItem as Item } from "../client/types.ts"
import { useMessages } from "../i18n/context.ts"
import type { AuthKitError } from "../client/errors.ts"
import { useTask } from "../react/task.ts"
import { useSession } from "../react/context.ts"
import {
  useNotificationUnread,
  useNotificationInbox,
  type NotificationInboxOptions,
} from "../react/notifications.ts"
import { AuthUiRoot } from "../scope.tsx"
import { useScopeProps } from "../scope-context.ts"
import { Badge } from "../ui/badge.tsx"
import { Button } from "../ui/button.tsx"
import { Spinner } from "../ui/spinner.tsx"
import { relativeTime } from "./account/lib.ts"

export interface NotificationInboxProps {
  /** Host-owned rendering for every kind, including unknown future kinds. */
  renderItem?: (item: Item) => ReactNode
  /** Domain actions/links; the inbox itself never executes a source's workflow. */
  renderActions?: (item: Item) => ReactNode
  pageSize?: number
  initialFilter?: "all" | "unread" | "archived"
  refreshInterval?: NotificationInboxOptions["refreshInterval"]
  onSignIn?: () => void
  onError?: (error: AuthKitError) => void
  className?: string
}

/** A user inbox with cursor pagination and independent local read state. */
export function NotificationInbox({
  renderItem,
  renderActions,
  pageSize,
  initialFilter = "all",
  refreshInterval,
  onSignIn,
  onError,
  className,
}: NotificationInboxProps) {
  const { t } = useMessages()
  const heading = useId()
  const [filter, setFilter] = useState(initialFilter)
  const inbox = useNotificationInbox({
    pageSize,
    unread: filter === "unread",
    dismissed: filter === "archived",
    refreshInterval,
  })
  const signIn = onSignIn
  const filterButton = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (inbox.error) onError?.(inbox.error)
  }, [inbox.error, onError])
  return (
    <AuthUiRoot
      className={cn("grid gap-4 text-sm", className)}
      data-authui="notification-inbox"
      role="region"
      aria-labelledby={heading}
    >
      <header className="flex items-center justify-between gap-3">
        <h2 id={heading} className="text-base font-semibold">
          {t("notifications.title")}
        </h2>
        {!inbox.signedOut && (
          <Button
            size="icon-sm"
            variant="ghost"
            aria-label={t("notifications.refresh")}
            disabled={inbox.loading}
            onClick={inbox.reload}
          >
            <HugeiconsIcon icon={RefreshIcon} strokeWidth={2} />
          </Button>
        )}
      </header>
      {inbox.signedOut ? (
        <div className="grid justify-items-start gap-3 py-4 text-muted-foreground">
          <p>{t("notifications.signInHint")}</p>
          {signIn && (
            <Button variant="outline" onClick={signIn}>
              {t("notifications.signIn")}
            </Button>
          )}
        </div>
      ) : (
        <>
          <div
            className="flex gap-1"
            role="group"
            aria-label={t("notifications.filter")}
          >
            {(["all", "unread", "archived"] as const).map((value) => (
              <Button
                key={value}
                ref={filter === value ? filterButton : undefined}
                size="sm"
                variant={filter === value ? "secondary" : "ghost"}
                aria-pressed={filter === value}
                onClick={() => setFilter(value)}
              >
                {t(`notifications.${value}`)}
              </Button>
            ))}
          </div>
          {inbox.error && (
            <div className="grid justify-items-start gap-2">
              <p role="alert" className="text-destructive">
                {t("notifications.loadFailed")}
              </p>
              <Button size="sm" variant="outline" onClick={inbox.reload}>
                {t("common.tryAgain")}
              </Button>
            </div>
          )}
          {inbox.loading && !inbox.items.length ? (
            <div
              role="status"
              aria-label={t("notifications.loading")}
              className="grid gap-3"
            >
              <Spinner className="size-5" />
              <Spinner className="size-5" />
            </div>
          ) : !inbox.items.length && !inbox.error ? (
            <p role="status" className="py-8 text-center text-muted-foreground">
              {t(
                filter === "unread"
                  ? "notifications.emptyUnread"
                  : "notifications.empty"
              )}
            </p>
          ) : (
            <ul
              className="grid divide-y divide-border overflow-hidden rounded-lg border border-border"
              aria-busy={inbox.loading}
            >
              {inbox.items.map((item) => (
                <NotificationRow
                  key={item.id}
                  item={item}
                  renderItem={renderItem}
                  renderActions={renderActions}
                  onRead={async (id, read) => {
                    const item = await inbox.setRead(id, read)
                    if (filter === "unread" && read)
                      filterButton.current?.focus()
                    return item
                  }}
                  onDismiss={async (id, dismissed) => {
                    const item = await inbox.setDismissed(id, dismissed)
                    filterButton.current?.focus()
                    return item
                  }}
                  onError={onError}
                />
              ))}
            </ul>
          )}
          {inbox.hasMore && (
            <Button
              variant="outline"
              disabled={inbox.loadingMore || inbox.loading}
              onClick={() => void inbox.loadMore()}
            >
              {t(
                inbox.loadingMore
                  ? "notifications.loading"
                  : "notifications.loadMore"
              )}
            </Button>
          )}
        </>
      )}
    </AuthUiRoot>
  )
}

function NotificationRow({
  item,
  renderItem,
  renderActions,
  onRead,
  onDismiss,
  onError,
}: Pick<NotificationInboxProps, "renderItem" | "renderActions" | "onError"> & {
  item: Item
  onRead: (id: string, read: boolean) => Promise<Item>
  onDismiss: (id: string, dismissed: boolean) => Promise<Item>
}) {
  const messages = useMessages()
  const { t } = messages
  const read = useTask()
  const dismiss = useTask()
  const error = read.error ?? dismiss.error
  useEffect(() => {
    if (error) onError?.(error)
  }, [error, onError])
  const label = useId()
  const status =
    item.status === "open"
      ? t("notifications.open")
      : item.status === "resolved"
        ? t("notifications.resolved")
        : item.status === "dismissed"
          ? t("notifications.dismissed")
          : undefined
  return (
    <li
      className={cn("grid gap-3 p-4", !item.read_at && "bg-primary/5")}
      data-authui="notification-item"
      data-unread={!item.read_at}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        {!item.read_at && (
          <Badge variant="secondary">{t("notifications.unread")}</Badge>
        )}
        {status && (
          <Badge variant={item.status === "open" ? "outline" : "secondary"}>
            {status}
          </Badge>
        )}
        <time
          dateTime={item.created_at}
          title={new Date(item.created_at).toLocaleString()}
        >
          {relativeTime(item.created_at)}
        </time>
      </div>
      <div id={label} className="min-w-0 break-words">
        {renderItem ? renderItem(item) : <NotificationMessage item={item} />}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {renderActions?.(item)}
        <Button
          size="sm"
          variant="ghost"
          aria-describedby={label}
          disabled={read.busy || dismiss.busy}
          onClick={() => void read.run(() => onRead(item.id, !item.read_at))}
        >
          {t(
            item.read_at ? "notifications.markUnread" : "notifications.markRead"
          )}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          aria-describedby={label}
          disabled={read.busy || dismiss.busy}
          onClick={() =>
            void dismiss.run(() => onDismiss(item.id, !item.dismissed_at))
          }
        >
          {t(
            item.dismissed_at
              ? "notifications.restore"
              : "notifications.dismiss"
          )}
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-destructive">
          {messages.error(error)}
        </p>
      )}
    </li>
  )
}

export interface NotificationBellProps extends NotificationInboxProps {
  /** Unread indicator refresh. Default 30 seconds while the page is visible. */
  unreadRefreshInterval?: NotificationInboxOptions["refreshInterval"]
}

/** A keyboard-accessible inbox popover. Its dot means unread items exist, not a guessed count. */
export function NotificationBell({
  className,
  unreadRefreshInterval,
  onError,
  ...inbox
}: NotificationBellProps) {
  const { t } = useMessages()
  const unread = useNotificationUnread({
    refreshInterval: unreadRefreshInterval,
  })
  const scope = useScopeProps()
  const session = useSession()
  const identity =
    session.status === "authenticated" ? session.userId : session.status
  useEffect(() => {
    if (unread.error) onError?.(unread.error)
  }, [unread.error, onError])
  if (unread.signedOut) return null
  return (
    <Popover.Root
      key={identity}
      onOpenChange={(open) => {
        if (open) unread.reload()
      }}
    >
      <AuthUiRoot
        className={cn("inline-flex", className)}
        data-authui="notification-bell"
      >
        <Popover.Trigger
          render={<Button variant="ghost" size="icon" />}
          aria-label={t(
            unread.unread ? "notifications.unreadLabel" : "notifications.title"
          )}
          className="relative"
        >
          <HugeiconsIcon icon={Notification01Icon} strokeWidth={2} />
          {unread.unread && (
            <span
              className="absolute right-1.5 top-1.5 size-2 rounded-full bg-primary ring-2 ring-background"
              aria-hidden="true"
              data-authui="notification-unread"
            />
          )}
        </Popover.Trigger>
      </AuthUiRoot>
      <Popover.Portal>
        <Popover.Positioner
          {...scope}
          className={cn(scope.className, "z-50")}
          sideOffset={8}
          align="end"
        >
          <Popover.Popup
            className="max-h-[min(80vh,40rem)] w-[min(26rem,calc(100vw-2rem))] overflow-auto rounded-xl border border-border bg-background p-4 text-foreground shadow-lg outline-none"
            aria-label={t("notifications.title")}
          >
            <NotificationInbox {...inbox} onError={onError} />
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  )
}

function NotificationMessage({ item }: { item: Item }) {
  const { t } = useMessages()
  const data =
    item.data && typeof item.data === "object" && !Array.isArray(item.data)
      ? (item.data as Record<string, unknown>)
      : {}
  const title =
    typeof data.title === "string" && data.title.trim() ? data.title : null
  const message =
    typeof data.message === "string" && data.message.trim()
      ? data.message
      : null
  return (
    <div className="grid gap-1">
      {title && <p className="font-medium">{title}</p>}
      {message ? (
        <p>{message}</p>
      ) : (
        !title && <p>{t("notifications.newNotice")}</p>
      )}
    </div>
  )
}
