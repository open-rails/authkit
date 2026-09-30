import { readFileSync } from "node:fs"

import { expect, it } from "vitest"

import { hasPermission, permMatches } from "./permissions.ts"

type Vector = { grant: string; permission: string; matches: boolean }

// The vectors Go's iam.Perm.Matches runs (iam/perm_vectors_test.go).
const vectors: Vector[] = JSON.parse(
  readFileSync(
    new URL("../../../iam/testdata/perm_vectors.json", import.meta.url),
    "utf8"
  )
)

it("has vectors", () => {
  expect(vectors.length).toBeGreaterThan(0)
})

it.each(vectors)(
  "permMatches($grant, $permission) is $matches",
  ({ grant, permission, matches }) => {
    expect(permMatches(grant, permission)).toBe(matches)
  }
)

it("hasPermission is true when any grant matches", () => {
  const byPermission = new Map<string, Vector[]>()
  for (const v of vectors) {
    const vs = byPermission.get(v.permission) ?? []
    byPermission.set(v.permission, [...vs, v])
  }
  for (const [permission, vs] of byPermission) {
    const grants = vs.map((v) => v.grant)
    expect(hasPermission(grants, permission), permission).toBe(
      vs.some((v) => v.matches)
    )
  }
  expect(hasPermission(undefined, "root:users:ban")).toBe(false)
  expect(hasPermission([], "root:users:ban")).toBe(false)
})
