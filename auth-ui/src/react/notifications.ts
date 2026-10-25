import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react"
import type { NotificationListOptions } from "../client/client.ts"
import type { NotificationPage } from "../client/types.ts"
import { useAuthClient, useSession } from "./context.ts"
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
