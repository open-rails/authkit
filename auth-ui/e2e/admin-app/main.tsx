/* eslint-disable react-refresh/only-export-components */
// Host for the admin specs. The path picks the fixture:
// /<mode>/<view>/<group>/…, the component's basePath being its first three
// segments. alone: the component with its history default; router: mounted
// in a React Router app through navigation; stepup: a write through a
// resumable guard.
import { useEffect, useMemo, useState, type ReactNode } from "react"
import { createRoot } from "react-dom/client"

import {
  createBrowserRouter,
  Link as HostLink,
  RouterProvider,
  useLocation,
  useNavigate,
} from "react-router"

import {
  ApiKeysAdmin,
  createAdminClient,
  MembersAdmin,
  OAuthClientsAdmin,
  RemoteApplicationsAdmin,
  RolesAdmin,
  type AdminNavigation,
} from "../../dist/admin.js"
import { createAuthClient } from "../../dist/client.js"
import {
  AuthUiProvider,
  StepUpProvider,
  useStepUpGuard,
} from "../../dist/index.js"
import { AuthProvider, useSession } from "../../dist/react.js"

const [, mode = "", view = "", group = ""] = location.pathname.split("/")
const basePath = `/${mode}/${view}/${group}`
const client = createAuthClient()
Object.assign(window, { authClient: client })

const params = new URLSearchParams(location.search)
const dark = params.get("theme") === "dark"
document.head.insertAdjacentHTML(
  "beforeend",
  `<meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { --background: oklch(0.98 0 0); --foreground: oklch(0.2 0 0); --primary: oklch(0.45 0.2 260); }
    .dark { --background: oklch(0.18 0 0); --foreground: oklch(0.95 0 0); --primary: oklch(0.7 0.15 260); }
    html, body { margin: 0; background: var(--background); color: var(--foreground); font-family: sans-serif; }
  </style>`
)
if (dark) document.documentElement.classList.add("dark")

function Login() {
  const [error, setError] = useState("")
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        const f = new FormData(e.currentTarget)
        await client
          .signInWithPassword({
            identifier: String(f.get("identifier")),
            password: String(f.get("password")),
          })
          .catch((err: { code?: string }) => setError(String(err.code ?? err)))
      }}
    >
      <input name="identifier" aria-label="identifier" />
      <input name="password" type="password" aria-label="password" />
      <button>sign in</button>
      <p data-testid="login-error">{error}</p>
    </form>
  )
}

function Shell({ children }: { children: ReactNode }) {
  const session = useSession()
  return (
    <main style={{ maxWidth: 960, margin: "0 auto", padding: "24px 16px" }}>
      <p data-testid="status" hidden>
        {session.status}
      </p>
      {session.status === "anonymous" && <Login />}
      {session.status === "authenticated" && children}
    </main>
  )
}

// A group OAuth client's creation needs a recent sign-in: the guard steps
// up, and a provider step-up replays it on return.
function StepUpProbe() {
  const guard = useStepUpGuard()
  const admin = useMemo(() => createAdminClient({ auth: client }), [])
  const kind = `e2e.create_client:${group}`
  const [log, setLog] = useState<string[]>([])
  const [error, setError] = useState("")
  useEffect(
    () =>
      guard.onResume?.(kind, async (data) => {
        const made = await admin.createOAuthClient(
          group,
          data as Parameters<typeof admin.createOAuthClient>[1]
        )
        setLog((l) => [...l, `resumed:${made.client_name}`])
      }),
    [guard, kind, admin]
  )
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        const input = {
          client_name: String(new FormData(e.currentTarget).get("name")),
          redirect_uris: ["https://shop.example/callback"],
          token_endpoint_auth_method: "none" as const,
          scope: "openid",
        }
        try {
          const made = await guard(
            () => admin.createOAuthClient(group, input),
            {
              resume: { kind, data: input },
            }
          )
          setLog((l) => [...l, `created:${made.client_name}`])
        } catch (err) {
          setError(String((err as { code?: string }).code ?? err))
        }
      }}
    >
      <input name="name" aria-label="client name" />
      <button>create client</button>
      <ul data-testid="log">
        {log.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      <p data-testid="error">{error}</p>
    </form>
  )
}

const VIEWS = {
  members: MembersAdmin,
  roles: RolesAdmin,
  "api-keys": ApiKeysAdmin,
  "oauth-clients": OAuthClientsAdmin,
  "remote-applications": RemoteApplicationsAdmin,
}

function Admin({ navigation }: { navigation?: AdminNavigation }) {
  const guard = useStepUpGuard()
  const View = VIEWS[view as keyof typeof VIEWS]
  if (!View) return <p>unknown view {view}</p>
  return (
    <View
      auth={client}
      group={group}
      basePath={basePath}
      navigation={navigation}
      guard={guard}
      language={params.get("lang") ?? undefined}
      {...(view === "roles" && {
        permissionHelp: {
          "billing:read": "Read billing",
          "billing:manage": "Change billing",
        },
      })}
    />
  )
}

// The host router: the component follows it and drives it.
function RouterHost() {
  const location = useLocation()
  const navigate = useNavigate()
  const navigation = useMemo<AdminNavigation>(
    () => ({
      pathname: location.pathname,
      search: location.search,
      navigate: (to, options) => void navigate(to, options),
    }),
    [location, navigate]
  )
  return (
    <>
      <nav>
        <HostLink to={basePath}>host: start</HostLink>{" "}
        <HostLink to={`${basePath}/invitations`}>host: invitations</HostLink>{" "}
        <HostLink to={`${basePath}/new`}>host: new</HostLink>
      </nav>
      <p data-testid="host-location">
        {location.pathname}
        {location.search}
      </p>
      <Admin navigation={navigation} />
    </>
  )
}

const hostRouter =
  mode === "router"
    ? createBrowserRouter([{ path: "*", element: <RouterHost /> }])
    : null

function App() {
  if (mode === "stepup") return <StepUpProbe />
  if (hostRouter) return <RouterProvider router={hostRouter} />
  return <Admin />
}

const root = document.createElement("div")
document.body.append(root)
createRoot(root).render(
  <AuthProvider client={client}>
    <AuthUiProvider>
      <StepUpProvider>
        <Shell>
          <App />
        </Shell>
      </StepUpProvider>
    </AuthUiProvider>
  </AuthProvider>
)
