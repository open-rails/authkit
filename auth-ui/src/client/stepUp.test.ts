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

it("reads another API client's step-up challenge without its error class", () => {
  const factors = [
    {
      id: "factor-1",
      method: "email",
      is_default: true,
      destination: "a***@b.c",
      future_field: true,
    },
  ]
  const error = Object.assign(new Error("Confirm it's you"), {
    name: "ApiError",
    status: 401,
    code: "step_up_required",
    metadata: {
      step_up_methods: [" Password ", "password", "2fa", "FutureProvider"],
      max_age_seconds: 900,
      factors,
      future_field: true,
    },
  })
  expect(readStepUpRequired(error)).toEqual({
    methods: ["password", "2fa", "futureprovider"],
    maxAgeSeconds: 900,
    factors,
  })
  expect(
    readStepUpRequired({
      status: 401,
      code: "step_up_required",
      metadata: { step_up_methods: ["password"] },
    })
  ).toEqual({ methods: ["password"], maxAgeSeconds: undefined, factors: [] })
  expect(errorMetadata(error, "step_up_required")).toBeNull()
})

it.each([
  null,
  new Error("step_up_required"),
  { status: 403, code: "step_up_required" },
  { status: "401", code: "step_up_required" },
  { status: 401, code: "invalid_credentials" },
  { status: 401, code: "step_up_required", metadata: null },
  ...[
    {},
    { step_up_methods: "password" },
    { step_up_methods: [] },
    { step_up_methods: [" "] },
    { step_up_methods: ["password", 1] },
    { step_up_methods: ["password"], max_age_seconds: "900" },
    { step_up_methods: ["password"], max_age_seconds: -1 },
    { step_up_methods: ["password"], max_age_seconds: NaN },
    { step_up_methods: ["password"], max_age_seconds: Infinity },
    { step_up_methods: ["2fa"], factors: {} },
    { step_up_methods: ["2fa"], factors: [null] },
    {
      step_up_methods: ["2fa"],
      factors: [{ id: "f1", method: "totp", is_default: true }],
    },
  ].map((metadata) => ({ status: 401, code: "step_up_required", metadata })),
])("ignores unrelated or malformed foreign challenges (%#)", (error) => {
  expect(readStepUpRequired(error)).toBeNull()
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
