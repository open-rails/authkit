import { describe, expect, it } from "vitest"

import { readAuthKitError } from "./errors.ts"

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })

describe("readAuthKitError", () => {
  it("decodes the AuthKit error envelope", async () => {
    const err = await readAuthKitError(
      json(429, {
        error: {
          type: "rate_limit_error",
          code: "rate_limited",
          message: "slow down",
          metadata: { retry_after_seconds: 12 },
        },
      })
    )
    expect(err.status).toBe(429)
    expect(err.code).toBe("rate_limited")
    expect(err.retryAfterSeconds).toBe(12)
  })

  it("falls back for non-envelope bodies", async () => {
    const err = await readAuthKitError(new Response("oops", { status: 502 }))
    expect(err.code).toBe("unknown_error")
    expect(err.message).toBe("HTTP 502")
  })
})
