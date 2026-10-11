// Every route the admin client calls must be in AuthKit's route catalog.
import { expect, it } from "vitest"

import { AUTHKIT_ROUTES } from "../client/generated/routes.ts"
import { ADMIN_ROUTES } from "./client.ts"

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
