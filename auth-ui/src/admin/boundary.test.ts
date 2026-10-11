// The customer entries' import graph never reaches the admin entry's code.
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"

import { expect, it } from "vitest"

const src = path.resolve(import.meta.dirname, "..")
const admin = path.join(src, "admin")
const CUSTOMER_ENTRIES = [
  "index.ts",
  "provider.tsx",
  "client/index.ts",
  "react/index.ts",
  "solana/index.ts",
]

const IMPORT =
  /(?:import|export)[^"'`]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["']/g

function resolve(from: string, spec: string): string | null {
  const base = spec.startsWith("#authui/")
    ? path.join(src, spec.slice("#authui/".length))
    : spec.startsWith(".")
      ? path.resolve(path.dirname(from), spec)
      : null
  if (!base) return null
  for (const candidate of [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    path.join(base, "index.ts"),
  ])
    if (existsSync(candidate) && candidate.match(/\.tsx?$/)) return candidate
  return null
}

it("customer entries import no admin module", () => {
  const seen = new Set<string>()
  const queue = CUSTOMER_ENTRIES.map((e) => path.join(src, e))
  while (queue.length) {
    const file = queue.pop()!
    if (seen.has(file)) continue
    seen.add(file)
    for (const m of readFileSync(file, "utf8").matchAll(IMPORT)) {
      const next = resolve(file, m[1] ?? m[2] ?? m[3])
      if (next) queue.push(next)
    }
  }
  expect(seen.size).toBeGreaterThan(50)
  expect([...seen].filter((f) => f.startsWith(admin + path.sep))).toEqual([])
})
