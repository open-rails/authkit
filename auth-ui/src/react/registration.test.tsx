// @vitest-environment jsdom
import { act, waitFor } from "@testing-library/react"
import { useEffect } from "react"
import { describe, expect, it } from "vitest"

import { json, stubFetch } from "../client/testing.ts"
import { useAuthClient, useSession } from "./context.ts"
import { renderWithAuth, signedIn } from "./testing.tsx"

describe("AuthProvider registration", () => {
  it("reports creation before user-change hooks, including a redirect completed on mount", async () => {
    const order: string[] = []
    const fetch = stubFetch({
      "POST /api/v1/oidc/exchange": [
        json(
          200,
          signedIn({ sub: "new-user", sid: "first" }, { created: true })
        ),
      ],
      "POST /api/v1/token": [
        json(
          200,
          signedIn({ sub: "new-user", sid: "first" }, { created: true })
        ),
      ],
    })
    const { client, result } = renderWithAuth(
      () => {
        const auth = useAuthClient()
        useEffect(() => {
          void auth.completeRedirect("#code=new&state=flow&provider=google")
        }, [auth])
        return useSession()
      },
      fetch,
      {
        onRegistered: ({ userId }) => order.push(`registered:${userId}`),
        onUserChange: (userId) => order.push(`user:${userId}`),
        onSessionChange: () => order.push("session"),
      }
    )
    await waitFor(() => expect(result.current.status).toBe("authenticated"))
    expect(order).toEqual(["registered:new-user", "user:new-user", "session"])
    await act(() => client.refresh())
    expect(order).toEqual(["registered:new-user", "user:new-user", "session"])
  })
})
