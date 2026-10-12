import { useCallback, useState } from "react"

import type { ListPage } from "../client/generated/wire.ts"
import { toAuthKitError } from "../react/task.ts"
import { useLoad } from "./load.ts"

// A cursor list: the first page while key is set, more on demand.
export function usePages<T>(
  key: string | null,
  page: (
    cursor: string | undefined,
    signal?: AbortSignal
  ) => Promise<ListPage<T>>
) {
  const first = useLoad(key, (signal) => page(undefined, signal))
  const [more, setMore] = useState<{
    key: string
    items: T[]
    next: string | null
  } | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const extra = more && more.key === key ? more : null
  const next = extra ? extra.next : (first.data?.next_cursor ?? null)
  const items = first.data
    ? [...first.data.data, ...(extra?.items ?? [])]
    : undefined
  const [moreError, setMoreError] = useState<unknown>(null)

  const loadMore = useCallback(async () => {
    if (!key || !next) return
    setLoadingMore(true)
    try {
      const p = await page(next)
      setMore((m) => ({
        key,
        items: [...(m && m.key === key ? m.items : []), ...p.data],
        next: p.next_cursor,
      }))
    } catch (err) {
      setMoreError(toAuthKitError(err))
    } finally {
      setLoadingMore(false)
    }
  }, [key, next, page])

  const { reload: reloadFirst } = first
  const reload = useCallback(() => {
    setMore(null)
    reloadFirst()
  }, [reloadFirst])

  return {
    items,
    next,
    error: first.error ?? moreError,
    loading: first.loading,
    loadingMore,
    loadMore: next ? loadMore : undefined,
    reload,
  }
}

// Page by page over a cursor list: page i is read with the cursor page i-1
// answered, so the pages seen and the one after are reachable. A new key
// starts again at page one.
export function useCursorPages<T>(
  key: string | null,
  page: (
    cursor: string | undefined,
    signal?: AbortSignal
  ) => Promise<ListPage<T>>
) {
  const [state, setState] = useState<{
    key: string | null
    cursors: (string | undefined)[]
    index: number
  }>({ key, cursors: [undefined], index: 0 })
  const current =
    state.key === key ? state : { key, cursors: [undefined], index: 0 }
  const cursor = current.cursors[current.index]
  const loaded = useLoad(
    key === null ? null : `${key}#${current.index}:${cursor ?? ""}`,
    (signal) => page(cursor, signal)
  )
  const next = loaded.data?.next_cursor
  return {
    items: loaded.data?.data,
    total: loaded.data?.total ?? null,
    page: current.index + 1,
    loading: loaded.loading,
    error: loaded.error,
    reload: loaded.reload,
    next: next
      ? () =>
          setState({
            key,
            cursors: [...current.cursors.slice(0, current.index + 1), next],
            index: current.index + 1,
          })
      : undefined,
    previous:
      current.index > 0
        ? () => setState({ ...current, index: current.index - 1 })
        : undefined,
  }
}
