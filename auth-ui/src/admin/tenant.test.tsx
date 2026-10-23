// @vitest-environment jsdom
import "../test/dom.ts"

import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, expect, it, vi } from "vitest"

import type { Guard, StepUpResumer } from "../react/task.ts"
import { AuthKitError } from "../client/errors.ts"
import { groupAccess, useUsersAdminAccess } from "./access.ts"
import { createAdminClient } from "./client.ts"
import { AdminRoot } from "./root.tsx"
import { UsersAdmin } from "./users.tsx"
import { AuthAdmin } from "./console.tsx"
import { useActions } from "./write.ts"
import { useLoad } from "./load.ts"

const TENANT_A = "11111111-1111-4111-8111-111111111111"
const TENANT_B = "455ef246-f041-4ff3-9938-df4a3d0a059e"
// The server answers group_id=root with the root group's own id.
const ROOT_ID = "019a0000-0000-7000-8000-000000000001"
const allPermissions = [
  "tenant:users:read",
  "tenant:users:manage",
  "tenant:users:ban",
  "tenant:users:delete",
  "tenant:users:invite",
  "tenant:members:read",
  "tenant:members:manage",
  "tenant:roles:read",
]
const user = (tenant = TENANT_A, username = "alice") => ({
  id: "account-id",
  tenant_id: tenant,
  tenant_role: "tenant:viewer",
  root_role: "root:owner",
  username,
  email: `${username}@example.test`,
  phone_number: null,
  email_verified: true,
  phone_verified: false,
  mfa_required: false,
  preferred_language: "en",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  last_login: null,
  deleted_at: null,
  ban: null,
  expired_ban: null,
  public_metadata: {},
  entitlements: [],
})

function host(permissions = allPermissions, rootPermissions: string[] = []) {
  const authFetch = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), location.href)
      if (url.pathname.endsWith("/me/permissions")) {
        const isRoot = url.searchParams.get("group_id") === "root"
        return Response.json({
          group_id: isRoot ? ROOT_ID : url.searchParams.get("group_id"),
          persona: isRoot ? "root" : "tenant",
          role: isRoot ? "root:admin" : "tenant:admin",
          permissions: isRoot ? rootPermissions : permissions,
        })
      }
      if (url.pathname.endsWith("/roles"))
        return Response.json({
          data: [
            { name: "tenant:viewer", permissions: [] },
            { name: "tenant:admin", permissions: allPermissions },
          ],
        })
      if (url.pathname.endsWith("/admin/users/account-id"))
        return Response.json(
          user(url.pathname.includes("/tenant-b/") ? TENANT_B : TENANT_A)
        )
      if (url.pathname.endsWith("/admin/users"))
        return Response.json({
          data: [
            user(url.pathname.includes("/tenant-b/") ? TENANT_B : TENANT_A),
          ],
          total: 1,
        })
      if (init?.method === "PUT") return Response.json({})
      return Response.json({ data: [], next_cursor: null })
    }
  )
  return { authFetch, auth: { authFetch } }
}

beforeEach(() => window.history.replaceState(null, "", "/users"))

it("keeps the source auth transport and scopes directory requests to the supplied mount", async () => {
  const { auth, authFetch } = host()
  const client = createAdminClient({ auth, baseUrl: "/tenant-a/auth/v1" })
  await client.listUsers({
    tenantRole: "tenant:viewer",
    rootRole: "root:auditor",
  })
  await client.getUser("account-id")
  const urls = authFetch.mock.calls.map(
    ([input]) => new URL(String(input), location.href)
  )
  expect(urls.map((url) => url.pathname)).toEqual([
    "/tenant-a/auth/v1/admin/users",
    "/tenant-a/auth/v1/admin/users/account-id",
  ])
  expect(urls[0].searchParams.get("tenant_role")).toBe("tenant:viewer")
  expect(urls[0].searchParams.get("root_role")).toBe("root:auditor")
  expect(
    authFetch.mock.calls.every(
      ([, init]) => !new Headers(init?.headers).has("tenant_id")
    )
  ).toBe(true)
})

it("accepts the root group's own id for a root permissions read in a tenant client", async () => {
  const { auth } = host(allPermissions, ["root:users:read"])
  const client = createAdminClient({ auth, tenantId: TENANT_A })
  await expect(client.permissions("root")).resolves.toMatchObject({
    group_id: ROOT_ID,
    persona: "root",
  })
})

it("refuses a non-root reply to a root permissions read", async () => {
  const auth = {
    authFetch: vi.fn(async () =>
      Response.json({
        group_id: TENANT_A,
        persona: "tenant",
        role: null,
        permissions: [],
      })
    ),
  }
  const client = createAdminClient({ auth, tenantId: TENANT_A })
  await expect(client.permissions("root")).rejects.toMatchObject({
    code: "tenant_scope_mismatch",
  })
})

it("gives different tenant clients distinct cache identities even at the same base URL", () => {
  const { auth } = host()
  const first = createAdminClient({ auth, tenantId: TENANT_A })
  const second = createAdminClient({ auth, tenantId: TENANT_B })
  expect(first.scopeKey).not.toBe(second.scopeKey)
})

it.each([undefined, TENANT_B])(
  "refuses missing or mismatched account ownership (%s) without changing the source session",
  async (tenantId) => {
    const entry = { ...user(), tenant_id: tenantId }
    const authFetch = vi.fn(async (input: RequestInfo | URL) =>
      Response.json(
        String(input).includes("account-id") ? entry : { data: [entry] }
      )
    )
    const auth = { authFetch, signOut: vi.fn(), refresh: vi.fn() }
    const client = createAdminClient({
      auth,
      baseUrl: "/tenant-a/auth/v1",
      tenantId: TENANT_A,
    })
    await expect(client.listUsers()).rejects.toMatchObject({
      code: "tenant_scope_mismatch",
    })
    await expect(client.getUser("account-id")).rejects.toMatchObject({
      code: "tenant_scope_mismatch",
    })
    expect(auth.signOut).not.toHaveBeenCalled()
    expect(auth.refresh).not.toHaveBeenCalled()
  }
)

it("refuses a permission answer for another group before loading accounts", async () => {
  const { auth } = host()
  const normal = auth.authFetch
  auth.authFetch = vi.fn(async (input, init) =>
    String(input).includes("/me/permissions")
      ? Response.json({
          group_id: TENANT_B,
          persona: "tenant",
          role: "root:owner",
          permissions: allPermissions,
        })
      : normal(input, init)
  )
  render(<UsersAdmin auth={auth} tenantId={TENANT_A} basePath="/users" />)
  await screen.findByText(/does not match the configured tenant/)
  expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument()
  expect(
    auth.authFetch.mock.calls.some(([input]) =>
      String(input).includes("/admin/users")
    )
  ).toBe(false)
})

it("validates the console's outer tenant scope before it can mount a user panel", async () => {
  const { auth } = host()
  const normal = auth.authFetch
  auth.authFetch = vi.fn(async (input, init) => {
    const url = new URL(String(input), location.href)
    if (url.searchParams.get("group_id") === TENANT_A) {
      return Response.json({
        group_id: TENANT_B,
        persona: "tenant",
        role: "root:owner",
        permissions: allPermissions,
      })
    }
    return normal(input, init)
  })
  render(
    <AuthAdmin
      auth={auth}
      basePath="/users"
      sections={["users"]}
      users={{ tenantId: TENANT_A }}
    />
  )
  await screen.findByText(/does not match the configured tenant/)
  expect(
    auth.authFetch.mock.calls.filter(([input]) =>
      String(input).includes(`group_id=${TENANT_A}`)
    )
  ).toHaveLength(1)
  expect(
    auth.authFetch.mock.calls.some(([input]) =>
      String(input).includes("/admin/users")
    )
  ).toBe(false)
})

it("uses the response persona instead of the global operator's role", () => {
  const set = {
    group_id: TENANT_A,
    persona: "tenant",
    role: "root:owner",
    permissions: allPermissions,
  }
  const access = groupAccess(TENANT_A, set)
  expect(access.persona).toBe("tenant")
  expect(access.members.manage).toBe(true)
  expect(access.roles.read).toBe(true)
})

it("uses tenant roles and invitations without requesting root membership", async () => {
  const { auth, authFetch } = host()
  render(
    <UsersAdmin
      auth={auth}
      tenantId={TENANT_A}
      baseUrl="/tenant-a/auth/v1"
      basePath="/users"
    />
  )
  await screen.findByRole("link", { name: "alice" })
  await userEvent
    .setup()
    .selectOptions(
      screen.getByRole("combobox", { name: "Tenant role" }),
      "tenant:viewer"
    )
  await waitFor(() =>
    expect(
      authFetch.mock.calls.some(([input]) =>
        String(input).includes("tenant_role=tenant%3Aviewer")
      )
    ).toBe(true)
  )
  await userEvent
    .setup()
    .click(screen.getByRole("link", { name: "Invitations" }))
  await screen.findByRole("heading", { name: "Sent invitations" })
  const urls = authFetch.mock.calls.map(([input]) => String(input))
  expect(
    urls.some((url) => url.includes(`/groups/${TENANT_A}/invitations`))
  ).toBe(true)
  expect(urls.some((url) => url.includes("/groups/root/"))).toBe(false)
})

it.each(["users", "console"])(
  "allows a global account reader in a tenant %s without granting tenant role access",
  async (panel) => {
    const { auth, authFetch } = host(
      [],
      [
        "root:users:read",
        "root:members:read",
        "root:members:manage",
        "root:roles:read",
        "root:credentials:manage",
      ]
    )
    if (panel === "users") {
      render(<UsersAdmin auth={auth} tenantId={TENANT_A} basePath="/users" />)
    } else {
      render(
        <AuthAdmin
          auth={auth}
          basePath="/users"
          sections={["users"]}
          users={{ tenantId: TENANT_A }}
        />
      )
    }
    await screen.findByRole("link", { name: "alice" })
    expect(
      screen.queryByRole("combobox", { name: "Tenant role" })
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("link", { name: "Invitations" })
    ).not.toBeInTheDocument()
    expect(
      authFetch.mock.calls.some(([input]) => String(input).includes("/roles"))
    ).toBe(false)
  }
)

it("recognizes roleless tenant account invitations without membership powers", () => {
  const access = groupAccess(TENANT_A, {
    group_id: TENANT_A,
    persona: "tenant",
    role: "tenant:inviter",
    permissions: ["tenant:users:invite"],
  })
  expect(access.invite).toBe(true)
  expect(access.members.manage).toBe(false)
  expect(access.roles.read).toBe(false)
})

it("shows sign-in methods, end reasons, devices and the language in words", async () => {
  window.history.replaceState(null, "", "/users/account-id")
  const mac =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
  const { auth: base } = host(allPermissions, ["root:users:read"])
  const authFetch = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith("/account-id/sessions"))
        return Response.json({
          data: [
            {
              id: "s1",
              created_at: "2026-01-02T00:00:00Z",
              last_used_at: "2026-01-02T00:00:00Z",
              ip: "127.0.0.1",
              user_agent: mac,
            },
          ],
          next_cursor: null,
        })
      if (path.endsWith("/account-id/session-events"))
        return Response.json({
          data: [
            {
              kind: "session_created",
              occurred_at: "2026-01-02T00:00:00Z",
              method: "password_login",
              ip: "127.0.0.1",
              user_agent: mac,
            },
            {
              kind: "session_revoked",
              occurred_at: "2026-01-01T00:00:00Z",
              reason: "contact_proven",
            },
            {
              kind: "session_revoked",
              occurred_at: "2026-01-01T00:00:00Z",
              reason: "logout",
              method: "future_method",
            },
            {
              kind: "session_created",
              occurred_at: "2026-01-01T00:00:00Z",
              method: "constructor",
            },
            {
              kind: "session_created",
              occurred_at: "2026-01-01T00:00:00Z",
              method: "passwordless_email",
            },
          ],
          next_cursor: null,
        })
      return base.authFetch(input, init)
    }
  )
  render(
    <UsersAdmin auth={{ authFetch }} tenantId={TENANT_A} basePath="/users" />
  )
  const history = await screen.findByRole("table", { name: "Sign-in history" })
  expect(within(history).getByText("Password")).toBeInTheDocument()
  expect(within(history).getByText(/Contact confirmed/)).toBeInTheDocument()
  // Unknown values show as sent; a plain sign-out adds no reason.
  expect(within(history).getByText("future_method")).toBeInTheDocument()
  expect(within(history).getByText("constructor")).toBeInTheDocument()
  expect(within(history).queryByText(/logout/)).not.toBeInTheDocument()
  expect(within(history).getAllByText("Chrome on macOS")[0]).toHaveAttribute(
    "title",
    mac
  )
  expect(screen.getByText("English")).toBeInTheDocument()
  expect(within(history).getByText("Email sign-in code")).toBeInTheDocument()
})

it("offers the host's languages by name in the profile editor", async () => {
  window.history.replaceState(null, "", "/users/account-id")
  const { auth } = host(allPermissions, [
    "root:users:read",
    "root:users:manage",
  ])
  render(
    <UsersAdmin
      auth={auth}
      tenantId={TENANT_A}
      basePath="/users"
      languages={["ja", "de"]}
    />
  )
  const actions = userEvent.setup()
  await actions.click(
    await screen.findByRole("button", { name: "Edit profile" })
  )
  const language = await screen.findByRole("combobox", { name: "Language" })
  // The account's "en" stays selectable beside the host's languages.
  expect(
    within(language)
      .getAllByRole("option")
      .map((o) => o.textContent)
  ).toEqual(["—", "Japanese", "German", "English"])
  expect(language).toHaveValue("en")
})

it("edits only the tenant role and never presents the account's root role", async () => {
  window.history.replaceState(null, "", "/users/account-id")
  const { auth, authFetch } = host()
  render(
    <UsersAdmin
      auth={auth}
      tenantId={TENANT_A}
      baseUrl="/tenant-a/auth/v1"
      basePath="/users"
    />
  )
  await screen.findByRole("heading", { name: "Tenant role" })
  expect(
    screen.queryByRole("heading", { name: "Root role" })
  ).not.toBeInTheDocument()
  expect(screen.getByRole("combobox", { name: "Tenant role" })).toHaveValue(
    "tenant:viewer"
  )
  const actions = userEvent.setup()
  await actions.selectOptions(
    screen.getByRole("combobox", { name: "Tenant role" }),
    "tenant:admin"
  )
  await actions.click(screen.getByRole("button", { name: "Save role" }))
  const dialog = await screen.findByRole("alertdialog")
  await actions.type(within(dialog).getByRole("textbox"), "alice")
  await actions.click(within(dialog).getByRole("button", { name: "Save role" }))
  await waitFor(() =>
    expect(
      authFetch.mock.calls.some(
        ([input, init]) =>
          String(input).endsWith(
            `/groups/${TENANT_A}/members/users/account-id`
          ) &&
          init?.method === "PUT" &&
          init.body === JSON.stringify({ role: "tenant:admin" })
      )
    ).toBe(true)
  )
  expect(
    authFetch.mock.calls.some(([input]) =>
      String(input).includes("/groups/root/")
    )
  ).toBe(false)
})

it("hides old data immediately and ignores late responses when the target changes", async () => {
  let finish!: (response: Response) => void
  let waiting = false
  const h = host()
  const normal = h.auth.authFetch
  h.auth.authFetch = vi.fn(async (input, init) => {
    if (
      String(input).includes("/tenant-a/") &&
      String(input).includes("/admin/users?")
    ) {
      waiting = true
      return new Promise<Response>((resolve) => {
        finish = resolve
      })
    }
    return normal(input, init)
  })
  const { rerender } = render(
    <UsersAdmin
      auth={h.auth}
      tenantId={TENANT_A}
      baseUrl="/tenant-a/auth/v1"
      basePath="/users"
    />
  )
  await waitFor(() => expect(waiting).toBe(true))
  rerender(
    <UsersAdmin
      auth={h.auth}
      tenantId={TENANT_B}
      baseUrl="/tenant-b/auth/v1"
      basePath="/users"
    />
  )
  await screen.findByRole("link", { name: "alice" })
  await act(async () =>
    finish(
      Response.json({ data: [user(TENANT_A, "old-tenant-secret")], total: 1 })
    )
  )
  expect(screen.queryByText("old-tenant-secret")).not.toBeInTheDocument()
  expect(screen.getByRole("link", { name: "alice" })).toBeInTheDocument()
})

it("sets an individual MFA requirement through the scoped user editor", async () => {
  window.history.replaceState(null, "", "/users/account-id")
  const h = host()
  const normal = h.auth.authFetch
  let update: unknown
  h.auth.authFetch = vi.fn(async (input, init) => {
    if (
      init?.method === "PATCH" &&
      String(input).endsWith("/admin/users/account-id")
    ) {
      update = JSON.parse(String(init.body))
      return Response.json({ ...user(), mfa_required: true })
    }
    return normal(input, init)
  })
  render(<UsersAdmin auth={h.auth} tenantId={TENANT_A} basePath="/users" />)
  const actions = userEvent.setup()
  await actions.click(
    await screen.findByRole("button", { name: "Edit profile" })
  )
  await actions.click(
    screen.getByRole("checkbox", { name: "Require two-factor authentication" })
  )
  await actions.click(screen.getByRole("button", { name: "Save" }))
  await waitFor(() => expect(update).toEqual({ mfa_required: true }))
})

it("resets a loaded account and an open editor even if only tenantId changes", async () => {
  window.history.replaceState(null, "", "/users/account-id")
  const { auth } = host()
  const { rerender } = render(
    <UsersAdmin auth={auth} tenantId={TENANT_A} basePath="/users" />
  )
  await screen.findByRole("heading", { name: "alice" })
  await userEvent
    .setup()
    .click(screen.getByRole("button", { name: "Edit profile" }))
  await screen.findByRole("dialog")
  rerender(<UsersAdmin auth={auth} tenantId={TENANT_B} basePath="/users" />)
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  expect(
    screen.queryByRole("heading", { name: "alice" })
  ).not.toBeInTheDocument()
  await screen.findByText(/does not match the configured tenant/)
  expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument()
})

it("unregisters old tenant action resumes and uses a different resume identity", async () => {
  const registered = new Map<string, StepUpResumer>()
  const guard: Guard = Object.assign(
    async <T,>(action: () => Promise<T>) => action(),
    {
      onResume: (key: string, resume: StepUpResumer) => {
        registered.set(key, resume)
        return () => {
          registered.delete(key)
        }
      },
    }
  )
  const write = vi.fn(async () => undefined)
  function Action() {
    useActions("authkit.user:account-id", { ban: write }, () => undefined)
    return null
  }
  const { auth } = host()
  const { rerender } = render(
    <AdminRoot auth={auth} guard={guard} tenantId={TENANT_A} basePath="/users">
      <Action />
    </AdminRoot>
  )
  const [first] = registered.keys()
  expect(first).toContain(TENANT_A)
  rerender(
    <AdminRoot auth={auth} guard={guard} tenantId={TENANT_B} basePath="/users">
      <Action />
    </AdminRoot>
  )
  expect(registered.has(first)).toBe(false)
  const [next] = registered.keys()
  expect(next).toContain(TENANT_B)
  expect(write).not.toHaveBeenCalled()
})

it("does not dispatch a guarded write after its target was replaced", async () => {
  let release!: () => Promise<unknown>
  const guard: Guard = <T,>(action: () => Promise<T>) =>
    new Promise<T>((resolve, reject) => {
      release = async () => {
        try {
          resolve(await action())
        } catch (error) {
          reject(error)
        }
      }
    })
  const write = vi.fn(async () => undefined)
  function Action() {
    const actions = useActions(
      "authkit.user:account-id",
      { ban: write },
      () => undefined
    )
    return (
      <button onClick={() => void actions.run("ban", undefined)}>
        Ban fixture
      </button>
    )
  }
  const { auth } = host()
  const { rerender } = render(
    <AdminRoot auth={auth} guard={guard} tenantId={TENANT_A} basePath="/users">
      <Action />
    </AdminRoot>
  )
  await userEvent
    .setup()
    .click(screen.getByRole("button", { name: "Ban fixture" }))
  rerender(
    <AdminRoot auth={auth} guard={guard} tenantId={TENANT_B} basePath="/users">
      <Action />
    </AdminRoot>
  )
  await act(async () => {
    await release()
  })
  expect(write).not.toHaveBeenCalled()
})

it("drops retained data when a reload proves the tenant binding is wrong", async () => {
  const load = vi
    .fn()
    .mockResolvedValueOnce("alice")
    .mockRejectedValue(
      new AuthKitError(0, {
        type: "local",
        code: "tenant_scope_mismatch",
        message: "wrong tenant",
      })
    )
  function Account() {
    const loaded = useLoad<string>("account", load)
    return (
      <>
        <span>{loaded.data ?? "no account"}</span>
        <span>{loaded.error?.code}</span>
        <button onClick={loaded.reload}>Reload</button>
      </>
    )
  }
  const { auth } = host()
  render(
    <AdminRoot auth={auth} tenantId={TENANT_A} basePath="/users">
      <Account />
    </AdminRoot>
  )
  await screen.findByText("alice")
  await userEvent.setup().click(screen.getByRole("button", { name: "Reload" }))
  await screen.findByText("tenant_scope_mismatch")
  expect(screen.queryByText("alice")).not.toBeInTheDocument()
})

it("offers host access checks for the explicit tenant", async () => {
  const { auth, authFetch } = host(["tenant:users:read"])
  function Access() {
    const access = useUsersAdminAccess({ auth, tenantId: TENANT_A })
    return (
      <span>
        {access.status === "ready" ? String(access.users.read) : access.status}
      </span>
    )
  }
  render(<Access />)
  await screen.findByText("true")
  expect(String(authFetch.mock.calls[0][0])).toContain(`group_id=${TENANT_A}`)
})
