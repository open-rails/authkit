// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import { authError, json, stubFetch } from "../../client/testing.ts"
import { memoryStorage } from "../../client/testing-storage.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { session } from "../../react/testing.tsx"
import { OAuthAuthorize } from "./OAuthAuthorize.tsx"

const pending = (extra: Record<string, unknown> = {}) =>
  json(200, {
    id: "a1",
    client_id: "console",
    client_name: "Console",
    scopes: ["api:jobs"],
    resource: null,
    prompt: [],
    max_age_seconds: null,
    login_hint: null,
    expires_at: "2030-01-01T00:00:00Z",
    ...extra,
  })

// A signed-in issuer page answering the pending request a1.
function renderAuthorize(routes: Parameters<typeof stubFetch>[0]) {
  const storage = memoryStorage()
  storage.setItem(
    "authkit:session:/api/v1",
    JSON.stringify({ userId: "u1", expiresAt: Date.now() + 60_000 })
  )
  const fetch = stubFetch({
    "POST /api/v1/token": [session({ sub: "u1", sid: "s1" })],
    "GET /api/v1/me": () => json(200, { id: "u1", username: "ann" }),
    ...routes,
  })
  const client = createAuthClient({ fetch, sessionHint: { storage } })
  const redirect = vi.fn()
  render(
    <AuthProvider client={client}>
      <AuthUiProvider>
        <OAuthAuthorize authorization="a1" redirect={redirect} />
      </AuthUiProvider>
    </AuthProvider>
  )
  return redirect
}

describe("OAuthAuthorize", () => {
  it("continues to a first-party client without asking", async () => {
    const approve = vi.fn(() =>
      json(200, { redirect_to: "https://c/cb?code=x" })
    )
    const redirect = renderAuthorize({
      "GET /api/v1/oauth2/authorizations/a1": [pending()],
      "POST /api/v1/oauth2/authorizations/a1/approve": approve,
    })
    await waitFor(() =>
      expect(redirect).toHaveBeenCalledWith("https://c/cb?code=x")
    )
  })

  it("accepts the client's agreements, then approves", async () => {
    const user = userEvent.setup()
    const terms = {
      key: "network-terms",
      version: "1",
      url: "https://openrails.test/terms",
    }
    const accepted: unknown[] = []
    const redirect = renderAuthorize({
      "GET /api/v1/oauth2/authorizations/a1": [
        pending({ agreements: [terms] }),
      ],
      "POST /api/v1/oauth2/authorizations/a1/approve": [
        authError(409, "agreement_required", { agreements: [terms] }),
        json(200, { redirect_to: "https://c/cb?code=y" }),
      ],
      "POST /api/v1/me/agreements": (init) => {
        accepted.push(JSON.parse(String(init.body)))
        return json(200, { accepted: [], due: [] })
      },
    })
    await screen.findByRole("heading", { name: "Review our terms" })
    await user.click(screen.getByRole("checkbox"))
    await user.click(
      screen.getByRole("button", { name: "Accept and continue" })
    )
    await waitFor(() =>
      expect(redirect).toHaveBeenCalledWith("https://c/cb?code=y")
    )
    expect(accepted).toEqual([
      { agreements: [{ key: "network-terms", version: "1" }] },
    ])
  })
})
