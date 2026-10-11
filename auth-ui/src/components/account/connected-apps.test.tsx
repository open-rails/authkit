// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import { json, stubFetch } from "../../client/testing.ts"
import { memoryStorage } from "../../client/testing-storage.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { noContent, session } from "../../react/testing.tsx"
import { ConnectedAppsPanel } from "./connected-apps-panel.tsx"

const shop = {
  client_id: "goc_aaaaaaaaaaaaaaaaaaaaaaaaaa",
  client_name: "Shop A",
  group_id: "g1",
  group_name: "Shop A Inc.",
  logo_uri: null,
  client_uri: null,
  scopes: ["openid", "email"],
  granted_at: "2026-10-10T00:00:00Z",
  updated_at: "2026-10-10T00:00:00Z",
}

function renderPanel(routes: Parameters<typeof stubFetch>[0]) {
  const storage = memoryStorage()
  storage.setItem(
    "authkit:session:/api/v1",
    JSON.stringify({ userId: "u1", expiresAt: Date.now() + 60_000 })
  )
  const fetch = stubFetch({
    "POST /api/v1/token": [session({ sub: "u1", sid: "s1" })],
    ...routes,
  })
  const client = createAuthClient({ fetch, sessionHint: { storage } })
  render(
    <AuthProvider client={client}>
      <AuthUiProvider>
        <ConnectedAppsPanel />
      </AuthUiProvider>
    </AuthProvider>
  )
  return fetch
}

describe("ConnectedAppsPanel", () => {
  it("lists connected apps and disconnects one", async () => {
    const user = userEvent.setup()
    const fetch = renderPanel({
      "GET /api/v1/me/oauth-consents": [
        json(200, { data: [shop], next_cursor: null, total: null }),
        json(200, { data: [], next_cursor: null, total: null }),
      ],
      [`DELETE /api/v1/me/oauth-consents/${shop.client_id}`]: [noContent()],
    })
    expect(await screen.findByText("Shop A Inc.")).toBeVisible()
    await user.click(screen.getByRole("button", { name: "Disconnect" }))
    const dialog = await screen.findByRole("alertdialog")
    await user.click(within(dialog).getByRole("button", { name: "Disconnect" }))
    await waitFor(() => expect(screen.queryByText("Shop A Inc.")).toBeNull())
    expect(
      fetch.mock.calls.some(
        ([url, init]) =>
          String(url).endsWith(`/me/oauth-consents/${shop.client_id}`) &&
          init?.method === "DELETE"
      )
    ).toBe(true)
  })

  it("shows nothing without connected apps", async () => {
    const fetch = renderPanel({
      "GET /api/v1/me/oauth-consents": [
        json(200, { data: [], next_cursor: null, total: null }),
      ],
    })
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    expect(screen.queryByText("Connected apps")).toBeNull()
  })
})
