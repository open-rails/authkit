// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import { json, stubFetch } from "../../client/testing.ts"
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
})
