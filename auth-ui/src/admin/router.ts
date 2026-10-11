import { createContext, useContext, useEffect, useMemo, useState } from "react"

// The host router as an admin component sees it: its location and a
// navigate. React Router: `{ pathname, search }` of useLocation() and
// useNavigate(). Without one, a component uses the history API.
export type AdminNavigation = {
  pathname: string
  search: string
  navigate(to: string, options?: { replace?: boolean }): void
}

// Lets every history-driven admin component on the page follow a push.
const NAVIGATED = "authkit:admin-navigate"

const here = () => ({
  pathname: window.location.pathname,
  search: window.location.search,
})

// The history API as an AdminNavigation: pushState, popstate.
export function useHistoryNavigation(): AdminNavigation {
  const [location, setLocation] = useState(here)
  useEffect(() => {
    const sync = () => setLocation(here())
    window.addEventListener("popstate", sync)
    window.addEventListener(NAVIGATED, sync)
    return () => {
      window.removeEventListener("popstate", sync)
      window.removeEventListener(NAVIGATED, sync)
    }
  }, [])
  return useMemo(
    () => ({
      ...location,
      navigate(to, options) {
        if (options?.replace) window.history.replaceState(null, "", to)
        else window.history.pushState(null, "", to)
        window.dispatchEvent(new Event(NAVIGATED))
      },
    }),
    [location]
  )
}

export type AdminRouter = {
  // The location beneath basePath: "" at basePath, else its segments.
  segments: string[]
  search: URLSearchParams
  // to is relative to basePath ("", "invitations", "a/b?x=1"), or a query
  // alone ("?role=x") for the current view.
  href(to: string): string
  navigate(to: string, options?: { replace?: boolean }): void
}

const RouterContext = createContext<AdminRouter | null>(null)

const trimSlashes = (s: string) => s.replace(/^\/+|\/+$/g, "")

export function createAdminRouter(
  basePath: string,
  navigation: AdminNavigation
): AdminRouter {
  const base = `/${trimSlashes(basePath)}`.replace(/^\/$/, "")
  const { pathname } = navigation
  const inside =
    pathname === base || pathname.startsWith(`${base}/`)
      ? pathname.slice(base.length)
      : ""
  const segments = trimSlashes(inside)
    .split("/")
    .filter(Boolean)
    .map(decodeURIComponent)
  const href = (to: string) => {
    if (to.startsWith("?"))
      return `${base}${segments.length ? `/${segments.map(encodeURIComponent).join("/")}` : ""}${to === "?" ? "" : to}`
    const path = trimSlashes(to)
    return `${base}${path ? `/${path}` : ""}` || "/"
  }
  return {
    segments,
    search: new URLSearchParams(navigation.search),
    href,
    navigate: (to, options) => navigation.navigate(href(to) || "/", options),
  }
}

export const RouterProvider = RouterContext.Provider

export function useRouter(): AdminRouter {
  const router = useContext(RouterContext)
  if (!router) throw new Error("auth-ui admin: rendered outside its root")
  return router
}

export function useNavigate() {
  return useRouter().navigate
}

// The query string, and a setter that keeps the view.
export function useSearchParams(): [
  URLSearchParams,
  (next: URLSearchParams, options?: { replace?: boolean }) => void,
] {
  const { search, navigate } = useRouter()
  return [
    search,
    (next, options) => {
      const qs = next.toString()
      navigate(qs ? `?${qs}` : "?", options)
    },
  ]
}
