// @vitest-environment jsdom
import "../test/dom.ts"

import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, expect, it, vi } from "vitest"

import { AuthAdmin } from "./index.ts"

beforeEach(() => window.history.replaceState(null, "", "/identity"))

function host(groupPermissions: string[], rootPermissions: string[] = []) {
  const authFetch = vi.fn(async (url: RequestInfo | URL) => {
    const target = new URL(String(url), window.location.href)
    if (target.pathname.endsWith("/me/permissions")) {
      const group = target.searchParams.get("group_id") ?? "root"
      return Response.json({
        group_id: group,
        role: group === "root" ? "root:staff" : "app:staff",
        permissions: group === "root" ? rootPermissions : groupPermissions,
      })
    }
    return Response.json({ data: [], next_cursor: null, total: 0 })
  })
  return { auth: { authFetch }, authFetch }
}

function requestedPaths(authFetch: ReturnType<typeof host>["authFetch"]) {
  return authFetch.mock.calls.map(
    ([url]) => new URL(String(url), location.href).pathname
  )
}

it("composes only permitted panels without granting root access to a group admin", async () => {
  const { auth, authFetch } = host(["app:members:read"])
  render(<AuthAdmin auth={auth} group="app-group" basePath="/identity" />)
  const nav = await screen.findByRole("navigation", {
    name: "Account administration",
  })
  expect(within(nav).getByRole("link", { name: "Members" })).toBeInTheDocument()
  expect(within(nav).getByRole("link", { name: "Roles" })).toBeInTheDocument()
  expect(
    within(nav).queryByRole("link", { name: "Users" })
  ).not.toBeInTheDocument()
  expect(
    within(nav).queryByRole("link", { name: "API keys" })
  ).not.toBeInTheDocument()
  await screen.findByRole("heading", { name: "Members" })
  expect(
    authFetch.mock.calls.some(([url]) => String(url).includes("/admin/users"))
  ).toBe(false)
  await userEvent
    .setup()
    .click(within(nav).getByRole("link", { name: "Roles" }))
  await waitFor(() => expect(window.location.pathname).toBe("/identity/roles"))
  await screen.findByRole("heading", { name: "Roles" })
})

it("defaults to root accounts and mounts only the selected panel", async () => {
  const { auth, authFetch } = host(
    [],
    ["root:users:read", "root:members:read", "root:credentials:read"]
  )
  render(<AuthAdmin auth={auth} basePath="/identity" />)
  await screen.findByRole("heading", { name: "Users" })
  await waitFor(() =>
    expect(requestedPaths(authFetch)).toContain("/api/v1/admin/users")
  )
  expect(requestedPaths(authFetch)).not.toContain("/api/v1/groups/root/members")
  expect(requestedPaths(authFetch)).not.toContain(
    "/api/v1/groups/root/api-keys"
  )
  expect(requestedPaths(authFetch)).not.toContain(
    "/api/v1/groups/root/oauth-clients"
  )
})

it.each([
  ["api-keys", "API keys"],
  ["oauth-clients", "OAuth clients"],
  ["remote-applications", "Signing keys"],
])(
  "opens the %s panel directly without mounting other credential views",
  async (section, title) => {
    window.history.replaceState(null, "", `/identity/${section}`)
    const { auth, authFetch } = host(["app:credentials:read"])
    render(<AuthAdmin auth={auth} group="app-group" basePath="/identity" />)
    await screen.findByRole("heading", { name: title, exact: true })
    await waitFor(() =>
      expect(requestedPaths(authFetch)).toContain(
        `/api/v1/groups/app-group/${section}`
      )
    )
    for (const other of [
      "api-keys",
      "oauth-clients",
      "remote-applications",
    ].filter((entry) => entry !== section)) {
      expect(requestedPaths(authFetch)).not.toContain(
        `/api/v1/groups/app-group/${other}`
      )
    }
  }
)

it("preserves panel deep links and browser back navigation", async () => {
  window.history.replaceState(null, "", "/identity/members/invitations")
  const { auth } = host(["app:members:read"])
  render(<AuthAdmin auth={auth} group="app-group" basePath="/identity" />)
  await screen.findByRole("heading", { name: "Sent invitations" })
  const nav = screen.getByRole("navigation", { name: "Account administration" })
  await userEvent
    .setup()
    .click(within(nav).getByRole("link", { name: "Roles" }))
  await screen.findByRole("heading", { name: "Roles" })
  act(() => window.history.back())
  await screen.findByRole("heading", { name: "Sent invitations" })
  expect(window.location.pathname).toBe("/identity/members/invitations")
})

it("denies a direct account link for a non-root group administrator", async () => {
  window.history.replaceState(null, "", "/identity/users/some-account")
  const { auth, authFetch } = host(["app:members:read", "app:credentials:read"])
  render(<AuthAdmin auth={auth} group="app-group" basePath="/identity" />)
  await screen.findByRole("heading", { name: "No access" })
  expect(
    requestedPaths(authFetch).filter(
      (path) => !path.endsWith("/me/permissions")
    )
  ).toEqual([])
})

it("honors explicit section exclusions even on direct links", async () => {
  window.history.replaceState(null, "", "/identity/users")
  const { auth, authFetch } = host([], ["root:users:read", "root:members:read"])
  render(
    <AuthAdmin
      auth={auth}
      basePath="/identity"
      users={false}
      sections={["users", "members"]}
    />
  )
  await screen.findByRole("heading", { name: "No access" })
  const nav = screen.getByRole("navigation", { name: "Account administration" })
  expect(
    within(nav).queryByRole("link", { name: "Users" })
  ).not.toBeInTheDocument()
  expect(within(nav).getByRole("link", { name: "Members" })).toBeInTheDocument()
  expect(
    within(nav).queryByRole("link", { name: "Roles" })
  ).not.toBeInTheDocument()
  expect(
    requestedPaths(authFetch).filter(
      (path) => !path.endsWith("/me/permissions")
    )
  ).toEqual([])
})

it("shows no-access without mounting a panel when no views are permitted", async () => {
  const { auth, authFetch } = host([])
  render(<AuthAdmin auth={auth} group="app-group" basePath="/identity" />)
  await screen.findByRole("heading", { name: "No access" })
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument()
  expect(
    requestedPaths(authFetch).filter(
      (path) => !path.endsWith("/me/permissions")
    )
  ).toEqual([])
})

it("discards old group permissions when the controlled scope changes", async () => {
  let grantOldGroup!: (response: Response) => void
  const oldPermissions = new Promise<Response>((resolve) => {
    grantOldGroup = resolve
  })
  const { auth, authFetch } = host([])
  const fetchOther = auth.authFetch
  auth.authFetch = vi.fn(async (input: RequestInfo | URL) => {
    const target = new URL(String(input), location.href)
    if (target.searchParams.get("group_id") === "old-group")
      return oldPermissions
    return fetchOther(input)
  })
  const { rerender } = render(
    <AuthAdmin auth={auth} group="old-group" basePath="/identity" />
  )
  await waitFor(() => expect(auth.authFetch).toHaveBeenCalled())
  rerender(<AuthAdmin auth={auth} group="new-group" basePath="/identity" />)
  await screen.findByRole("heading", { name: "No access" })
  await act(async () =>
    grantOldGroup(
      Response.json({
        group_id: "old-group",
        role: "app:staff",
        permissions: ["app:members:read"],
      })
    )
  )
  expect(
    screen.queryByRole("heading", { name: "Members" })
  ).not.toBeInTheDocument()
  expect(
    requestedPaths(authFetch).filter(
      (path) => !path.endsWith("/me/permissions")
    )
  ).toEqual([])
})

it("resets account permissions when the host changes the account key", async () => {
  const first = host([], ["root:users:read"])
  const next = host([])
  const { rerender } = render(
    <AuthAdmin key="first-account" auth={first.auth} basePath="/identity" />
  )
  await screen.findByRole("heading", { name: "Users" })
  rerender(
    <AuthAdmin key="next-account" auth={next.auth} basePath="/identity" />
  )
  await screen.findByRole("heading", { name: "No access" })
  expect(
    screen.queryByRole("heading", { name: "Users" })
  ).not.toBeInTheDocument()
  expect(
    requestedPaths(next.authFetch).filter(
      (path) => !path.endsWith("/me/permissions")
    )
  ).toEqual([])
})
