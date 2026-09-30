import { expect, it } from "vitest"

import { toSignInResult } from "./authResult.ts"
import { AuthKitError, errorMetadata } from "./errors.ts"
import { safeReturnTo } from "./returnTo.ts"
import { readStepUpRequired, stepUpDestination } from "./stepUp.ts"
import { authResult, complete } from "./testing.ts"

const err = (status: number, code: string, metadata: Record<string, unknown>) =>
  new AuthKitError(status, { type: "", code, message: code, metadata })

it("reads step_up_required and narrows MFA-gated methods to 2fa", () => {
  expect(
    readStepUpRequired(
      err(403, "step_up_required", {
        step_up_methods: ["password", "Google"],
        max_age_seconds: 300,
        step_up_2fa: null,
        mfa_required: false,
      })
    )
  ).toEqual({
    methods: ["password", "google"],
    mfaRequired: false,
    maxAgeSeconds: 300,
    twoFactor: undefined,
  })
  const twoFactor = {
    methods: ["totp", "email"],
    default_method: "totp",
    options: [
      { method: "totp", is_default: true, destination: null },
      { method: "email", is_default: false, destination: "a***@b.c" },
    ],
  }
  const challenge = readStepUpRequired(
    err(403, "step_up_required", {
      step_up_methods: ["password", "2fa"],
      max_age_seconds: 300,
      mfa_required: true,
      step_up_2fa: twoFactor,
    })
  )
  expect(challenge).toMatchObject({
    methods: ["2fa"],
    mfaRequired: true,
    twoFactor,
  })
  expect(stepUpDestination(challenge!, "email")).toBe("a***@b.c")
  expect(stepUpDestination(challenge!, "sms")).toBeNull()
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
