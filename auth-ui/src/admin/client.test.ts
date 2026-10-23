// Every route the admin client calls must be in AuthKit's route catalog.
import { describe, expect, it } from "vitest"

import { AUTHKIT_ROUTES } from "../client/generated/routes.ts"
import { ADMIN_ROUTES } from "./client.ts"
import { browserAndOS } from "./format.ts"

const catalog = AUTHKIT_ROUTES.map(({ method, path }) => ({
  method,
  pattern: new RegExp(`^${path.replace(/\{[^}]+\}/g, "[^/]+")}$`),
}))

it("calls only routes AuthKit's catalog declares", () => {
  for (const [name, [method, path]] of Object.entries(ADMIN_ROUTES)) {
    const concrete = `/api/v1${path.replace(/\{[^}]+\}/g, "x")}`
    expect(
      catalog.some((r) => r.method === method && r.pattern.test(concrete)),
      `${name}: ${method} ${path}`
    ).toBe(true)
  }
})

describe("browserAndOS", () => {
  it.each([
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1",
      { browser: "Chrome", os: "iOS" },
    ],
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/130.0 Mobile/15E148 Safari/605.1.15",
      { browser: "Firefox", os: "iOS" },
    ],
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/130.0 Mobile/15E148 Safari/605.1.15",
      { browser: "Edge", os: "iOS" },
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0",
      { browser: "Edge", os: "Windows" },
    ],
    [
      "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
      { browser: "Chrome", os: "Android" },
    ],
    [
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0 Safari/537.36",
      null,
    ],
    ["curl/8.7.1", null],
  ])("%s", (ua, want) => expect(browserAndOS(ua)).toEqual(want))
})
