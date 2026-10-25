import { useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import {
  createAuthClient,
  createIssuerClient,
  transportFailure,
  readAuthKitError,
} from "@openrails/auth-ui/client"
import { createAdminClient } from "@openrails/auth-ui/admin"
import {
  AccountSecurity,
  NotificationBell,
  NotificationInbox,
  AuthUiProvider,
  SignInDialog,
} from "@openrails/auth-ui"
import {
  AuthProvider,
  useSession,
  useUser,
  useNotifications,
} from "@openrails/auth-ui/react"

const params = new URLSearchParams(location.search)
const baseUrl = params.has("limited")
  ? "/limited/api/v1"
  : params.has("unproved")
    ? "/unproved/api/v1"
    : "/api/v1"
// Transparent public-boundary coverage only: real methods and results are
// unchanged. No arguments, credentials or response data are recorded.
function observe<T extends object>(target: T, boundary: string): T {
  const wrappers = new Map<PropertyKey, unknown>()
  return new Proxy(target, {
    get(object, property, receiver) {
      const value = Reflect.get(object, property, receiver)
      if (property === "notifications" && value && typeof value === "object") {
        if (!wrappers.has(property))
          wrappers.set(property, observe(value, `${boundary}.notifications`))
        return wrappers.get(property)
      }
      if (typeof value !== "function") return value
      if (!wrappers.has(property))
        wrappers.set(property, (...args: unknown[]) => {
          void window
            .__criticalMethod?.(`${boundary}.${String(property)}`)
            .catch(() => {})
          return Reflect.apply(value, object, args)
        })
      return wrappers.get(property)
    },
  })
}
const client = observe(
  createAuthClient({
    baseUrl,
    dpop: params.has("bound"),
    refreshLeadSeconds: 5,
  }),
  "AuthClient"
)
const issuer = observe(
  createIssuerClient({
    issuer: location.origin,
    clientId: "critical-issuer",
    redirectUri: "/issuer-return",
    scope: "openid profile email",
    persist: false,
    dpop: true,
  }),
  "IssuerClient"
)
if (location.pathname === "/issuer-return") {
  void issuer.completeSignIn()
}
const events: {
  kind: string
  userId?: string
  status?: string
  hasAccessToken?: boolean
  profileUserId?: string
  email?: string
}[] = []
client.onRegistered(({ userId }) =>
  events.push({
    kind: "registered",
    userId,
    status: client.getSnapshot().status,
    hasAccessToken: !!client.getAccessToken(),
  })
)
client.subscribe(() =>
  events.push({ kind: "session", status: client.getSnapshot().status })
)
const admin = observe(
  createAdminClient({ auth: client, baseUrl }),
  "AdminClient"
)
Object.assign(window, {
  ak: {
    client,
    issuer,
    admin,
    events,
    createAuthClient,
    createAdminClient,
    transportFailure,
    readAuthKitError,
  },
})

function NotificationProbe() {
  const inbox = useNotifications()
  return (
    <>
      <output data-testid="notification-count">{inbox.items.length}</output>
      <output data-testid="notification-first">
        {inbox.items[0]?.id ?? ""}
      </output>
    </>
  )
}

export function App() {
  const session = useSession()
  const { user } = useUser()
  const [open, setOpen] = useState(false)
  const scopeUser =
    session.status === "authenticated" ? session.userId : undefined
  useEffect(() => {
    events.push({
      kind: "profile",
      userId: scopeUser,
      profileUserId: user?.id,
      email: user?.email ?? undefined,
    })
  }, [scopeUser, user?.id, user?.email])
  return (
    <main>
      <output data-testid="session-status">{session.status}</output>
      <output data-testid="session-user">
        {session.status === "authenticated" ? session.userId : ""}
      </output>
      {params.has("notifications") && <NotificationProbe />}
      {params.has("notification-widgets") && (
        <>
          <NotificationBell renderItem={(item) => <p>{item.origin.id}</p>} />
          <div data-testid="notification-inbox">
            <NotificationInbox
              pageSize={1}
              renderItem={(item) => <p>{item.origin.id}</p>}
            />
          </div>
        </>
      )}
      <output data-testid="profile-email">{user?.email ?? ""}</output>
      <button onClick={() => setOpen(true)}>Open sign in</button>
      <button onClick={() => void client.signOut()}>Sign out</button>
      <SignInDialog
        open={open}
        onOpenChange={setOpen}
        initialTab={params.has("register") ? "register" : "login"}
      />
      {session.status === "authenticated" && (
        <AccountSecurity
          sections={["contact", "twoFactor", "delete"]}
          onDeleted={() => events.push({ kind: "deleted" })}
        />
      )}
    </main>
  )
}

createRoot(document.getElementById("root")!).render(
  <AuthProvider client={client}>
    <AuthUiProvider>
      <App />
    </AuthUiProvider>
  </AuthProvider>
)
