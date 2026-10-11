import { expect, it } from "vitest"

import { de } from "./de.ts"
import { en } from "./en.ts"
import { es } from "./es.ts"
import { ja } from "./ja.ts"
import { ko } from "./ko.ts"
import { zh } from "./zh.ts"

const flatten = (tree: object, prefix = ""): Record<string, string> =>
  Object.fromEntries(
    Object.entries(tree).flatMap(([k, v]) =>
      typeof v === "string"
        ? [[prefix + k, v]]
        : Object.entries(flatten(v, `${prefix}${k}.`))
    )
  )
const english = flatten(en)
const placeholders = (s: string) =>
  [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()

it.each(Object.entries({ de, es, ja, ko, zh }))(
  "%s covers every English key with its placeholders",
  (_, bundle) => {
    const own = flatten(bundle)
    expect(Object.keys(own).sort()).toEqual(Object.keys(english).sort())
    for (const [key, value] of Object.entries(own))
      expect(placeholders(value), key).toEqual(placeholders(english[key]))
  }
)
