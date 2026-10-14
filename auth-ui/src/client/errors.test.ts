import { describe, expect, it } from "vitest"

import { readAuthKitError, transportFailure } from "./errors.ts"

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
    const err = await readAuthKitError(new Response("oops", { status: 500 }))
    expect(err.code).toBe("unknown_error")
    expect(err.message).toBe("HTTP 500")
  })

  it("reads a gateway's non-envelope answer as server_unavailable", async () => {
    for (const status of [502, 503, 504, 522]) {
      const err = await readAuthKitError(new Response("<html>", { status }))
      expect(err.code, String(status)).toBe("server_unavailable")
    }
  })

  it("keeps a coded 503 from AuthKit as sent", async () => {
    const err = await readAuthKitError(
      json(503, {
        error: { type: "api_error", code: "server_busy", message: "busy" },
      })
    )
    expect(err.code).toBe("server_busy")
    expect(transportFailure(err)).toBeUndefined()
  })
})

describe("transportFailure", () => {
  it("classifies fetch rejections as network_error", () => {
    for (const message of [
      "Failed to fetch",
      "NetworkError when attempting to fetch resource.",
      "Load failed",
    ])
      expect(transportFailure(new TypeError(message)), message).toBe(
        "network_error"
      )
  })

  it("classifies timeouts and gateway statuses as server_unavailable", () => {
    expect(
      transportFailure(new DOMException("timed out", "TimeoutError"))
    ).toBe("server_unavailable")
    expect(transportFailure({ status: 504 })).toBe("server_unavailable")
  })

  it("leaves other failures alone", () => {
    expect(
      transportFailure(new TypeError("x.map is not a function"))
    ).toBeUndefined()
    expect(transportFailure(new DOMException("", "AbortError"))).toBeUndefined()
    expect(transportFailure({ status: 500 })).toBeUndefined()
    expect(transportFailure(new Error("boom"))).toBeUndefined()
  })
})
