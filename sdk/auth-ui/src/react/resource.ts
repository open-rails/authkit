import { AuthKitError } from "../client/errors.ts"
import { toAuthKitError } from "./task.ts"

export type ResourceSnapshot<T> = {
  // The key the data/error belong to; null = nothing requested.
  key: string | null
  data: T | null
  error: AuthKitError | null
  loading: boolean
}

// One shared, key-scoped fetch (e.g. /me per session). A newer key aborts and
// supersedes an older load; `null` results mean "stale, ignore".
export function createResource<T>(
  load: (signal: AbortSignal) => Promise<T | null>
) {
  let snap: ResourceSnapshot<T> = {
    key: null,
    data: null,
    error: null,
    loading: false,
  }
  let controller: AbortController | null = null
  let started = false
  const listeners = new Set<() => void>()
  const set = (next: Partial<ResourceSnapshot<T>>) => {
    snap = { ...snap, ...next }
    for (const l of listeners) l()
  }

  const fetchFor = (key: string): Promise<void> => {
    controller?.abort()
    const ctl = new AbortController()
    controller = ctl
    started = true
    set({
      key,
      loading: true,
      ...(snap.key === key ? {} : { data: null, error: null }),
    })
    return load(ctl.signal).then(
      (data) => {
        if (controller !== ctl) return
        controller = null
        if (data === null) set({ loading: false })
        else set({ data, error: null, loading: false })
      },
      (err: unknown) => {
        if (controller !== ctl) return
        controller = null
        set({ error: toAuthKitError(err), loading: false })
      }
    )
  }

  return {
    subscribe(listener: () => void) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    getSnapshot: () => snap,
    // Loads key unless it is already loaded or loading.
    ensure(key: string | null) {
      if (key === null) {
        controller?.abort()
        controller = null
        started = false
        if (snap.key !== null)
          set({ key: null, data: null, error: null, loading: false })
        return
      }
      if (snap.key === key && started) return
      void fetchFor(key)
    },
    reload(): Promise<void> {
      return snap.key === null ? Promise.resolve() : fetchFor(snap.key)
    },
  }
}

export type Resource<T> = ReturnType<typeof createResource<T>>
