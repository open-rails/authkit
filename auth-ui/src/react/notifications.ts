import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react"
import type { AuthClient, NotificationListOptions } from "../client/client.ts"
import type { NotificationItem, NotificationPage } from "../client/types.ts"
import { sessionIdentity, useAuthClient, useSession } from "./context.ts"
import { createResource } from "./resource.ts"

// useNotifications is one account-scoped page. Pass its nextCursor to another
// page request; changing the session immediately hides the previous account.
export function useNotifications(options: NotificationListOptions = {}) {
  const client = useAuthClient()
  const session = useSession()
  const user = session.status === "authenticated" ? session.userId : null
  const { limit, cursor, unread, dismissed } = options
  const resource = useMemo(
    () =>
      createResource<NotificationPage>((signal) =>
        client.notifications.list({ limit, cursor, unread, dismissed }, signal)
      ),
    [client, limit, cursor, unread, dismissed]
  )
  const snapshot = useSyncExternalStore(
    resource.subscribe,
    resource.getSnapshot,
    resource.getSnapshot
  )
  useEffect(() => {
    resource.ensure(user)
    return () => {
      resource.ensure(null)
    }
  }, [resource, user])
  useEffect(
    () =>
      client.notifications.subscribe(() => {
        void resource.reload()
      }),
    [client, resource]
  )
  const current = user !== null && snapshot.key === user
  return {
    items: current ? (snapshot.data?.items ?? []) : [],
    nextCursor: current ? (snapshot.data?.next_cursor ?? "") : "",
    loading: current && snapshot.loading,
    error: current ? snapshot.error : null,
    refresh: useCallback(() => resource.reload(), [resource]),
    setRead: client.notifications.setRead,
    setDismissed: client.notifications.setDismissed,
  }
}

export interface NotificationInboxOptions {
  pageSize?: number
  unread?: boolean
  dismissed?: boolean
  /** Refresh while visible. Off by default so loaded pages remain stable. */
  refreshInterval?: number | false
}

function inboxResource(
  client: AuthClient,
  identity: string | null,
  options: NotificationInboxOptions
) {
  let pages = 1
  const resource = createResource<NotificationPage>(async (signal) => {
    if (identity === null || sessionIdentity(client.getSnapshot()) !== identity)
      return null
    const items = new Map<string, NotificationItem>()
    let cursor: string | undefined
    for (let page = 0; page < pages; page++) {
      const result = await client.notifications.list(
        {
          limit: options.pageSize ?? 20,
          unread: options.unread,
          dismissed: options.dismissed,
          cursor,
        },
        signal
      )
      for (const item of result.items) items.set(item.id, item)
      cursor = result.next_cursor || undefined
      if (!cursor) break
    }
    return { items: [...items.values()], next_cursor: cursor ?? "" }
  })
  return {
    ...resource,
    loadMore: () => {
      const snapshot = resource.getSnapshot()
      if (snapshot.loading || !snapshot.data?.next_cursor)
        return Promise.resolve()
      pages++
      return resource.reload()
    },
  }
}

/** Cursor-paged inbox belonging to the current AuthProvider session. */
export function useNotificationInbox(options: NotificationInboxOptions = {}) {
  const client = useAuthClient()
  const session = useSession()
  const identity =
    session.status === "authenticated" ? sessionIdentity(session) : null
  const { pageSize, unread, dismissed, refreshInterval = false } = options
  const resource = useMemo(
    () => inboxResource(client, identity, { pageSize, unread, dismissed }),
    [client, identity, pageSize, unread, dismissed]
  )
  const snapshot = useSyncExternalStore(
    resource.subscribe,
    resource.getSnapshot,
    resource.getSnapshot
  )
  useEffect(() => {
    resource.ensure(identity)
    return () => resource.ensure(null)
  }, [resource, identity])
  useEffect(
    () =>
      client.notifications.subscribe(() => {
        void resource.reload()
      }),
    [client, resource]
  )
  useEffect(() => {
    if (identity === null || refreshInterval === false || refreshInterval <= 0)
      return
    const timer = setInterval(
      () => {
        if (document.visibilityState === "visible")
          client.notifications.refresh()
      },
      Math.max(5000, refreshInterval)
    )
    return () => clearInterval(timer)
  }, [client, identity, refreshInterval])
  const current = identity !== null && snapshot.key === identity
  return {
    items: current ? (snapshot.data?.items ?? []) : [],
    signedOut: identity === null,
    loading: identity !== null && (!current || snapshot.loading),
    loadingMore:
      current && snapshot.loading && Boolean(snapshot.data?.items.length),
    error: current ? snapshot.error : null,
    hasMore: current && Boolean(snapshot.data?.next_cursor),
    reload: client.notifications.refresh,
    loadMore: resource.loadMore,
    setRead: client.notifications.setRead,
    setDismissed: client.notifications.setDismissed,
  }
}

/** A bounded unread-present indicator, not a guessed total count. */
export function useNotificationUnread(
  options: Pick<NotificationInboxOptions, "refreshInterval"> = {}
) {
  const inbox = useNotificationInbox({
    refreshInterval: 30000,
    ...options,
    unread: true,
    pageSize: 1,
  })
  return {
    unread: inbox.items.length > 0,
    signedOut: inbox.signedOut,
    loading: inbox.loading,
    error: inbox.error,
    reload: inbox.reload,
  }
}
