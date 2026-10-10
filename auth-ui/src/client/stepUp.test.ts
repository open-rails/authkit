import { expect, it } from "vitest"

import { toSignInResult } from "./authResult.ts"
import { AuthKitError, errorMetadata } from "./errors.ts"
import { safeReturnTo } from "./returnTo.ts"
import { readStepUpRequired } from "./stepUp.ts"
import { authResult, complete } from "./testing.ts"

const err = (status: number, code: string, metadata: Record<string, unknown>) =>
  new AuthKitError(status, { type: "", code, message: code, metadata })

it("reads step_up_required with its second factors", () => {
  expect(
    readStepUpRequired(
      err(401, "step_up_required", {
        step_up_methods: ["password", "Google"],
        max_age_seconds: 300,
        factors: [],
      })
    )
  ).toEqual({
    methods: ["password", "google"],
    maxAgeSeconds: 300,
    factors: [],
  })
  const factors = [
    { id: "f1", method: "totp", is_default: true, destination: null },
    { id: "f2", method: "email", is_default: false, destination: "a***@b.c" },
  ]
  expect(
    readStepUpRequired(
      err(401, "step_up_required", {
        step_up_methods: ["2fa"],
        max_age_seconds: 300,
        factors,
      })
    )
  ).toEqual({ methods: ["2fa"], maxAgeSeconds: 300, factors })
  expect(readStepUpRequired(err(401, "invalid_credentials", {}))).toBeNull()
})

it("types error metadata by code", () => {
  const e = err(403, "verification_required", {
    identifier: "a@b.c",
    channel: "email",
    reason: "contact_unproven",
  })
  expect(errorMetadata(e, "verification_required")?.reason).toBe(
    "contact_unproven"
  )
  expect(errorMetadata(e, "step_up_required")).toBeNull()
  expect(errorMetadata(new Error("x"), "rate_limited")).toBeNull()
})

it("accepts an AuthResult only with its status's step", () => {
  expect(toSignInResult(complete("u")).status).toBe("complete")
  expect(() => toSignInResult(authResult("complete"))).toThrow()
  expect(() => toSignInResult(authResult("enrollment_required"))).toThrow()
  expect(() => toSignInResult({ access_token: "flat" })).toThrow()
  expect(() => toSignInResult(undefined)).toThrow()
})

it("keeps only app-relative return targets", () => {
  const origin = "https://app.test"
  expect(safeReturnTo("/a?b=1#c", origin)).toBe("/a?b=1#c")
  expect(safeReturnTo("https://app.test/a", origin)).toBe("/a")
  expect(safeReturnTo("//evil.example/a", origin)).toBeNull()
  expect(safeReturnTo("https://evil.example/a", origin)).toBeNull()
  expect(safeReturnTo("/\\evil.example", origin)).toBeNull()
})
