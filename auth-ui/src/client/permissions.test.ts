import { expect, it } from "vitest"

import { hasPermission } from "./permissions.ts"

it("is membership in the expanded permission set", () => {
  const granted = ["root:users:read", "root:users:ban"]
  expect(hasPermission(granted, "root:users:ban")).toBe(true)
  expect(hasPermission(granted, "root:users:delete")).toBe(false)
  // Patterns are not grants: the set is already expanded.
  expect(hasPermission(["root:*"], "root:users:ban")).toBe(false)
  expect(hasPermission(undefined, "root:users:ban")).toBe(false)
  expect(hasPermission([], "root:users:ban")).toBe(false)
})
