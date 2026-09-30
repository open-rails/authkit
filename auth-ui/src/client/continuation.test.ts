import { expect, it } from "vitest"

import { readContinuation, readStepUpRequired } from "./continuation.ts"
import { AuthKitError } from "./errors.ts"
import { safeReturnTo } from "./returnTo.ts"

const err = (status: number, code: string, metadata: Record<string, unknown>) =>
  new AuthKitError(status, { type: "", code, message: code, metadata })

// Shapes from authkit internal/apitest/testdata/wire/mfa-*.json.
it("reads the wire 2fa_required and enrollment envelopes", () => {
  expect(
    readContinuation(
      err(403, "2fa_required", {
        user_id: "u",
        challenge: "c",
        method: "totp",
        verification_id: "",
        default_factor: { id: "f", method: "totp" },
        available_factors: [
          { id: "f", method: "totp" },
          { id: "g", method: "sms" },
          { nope: 1 },
        ],
        return_to: "/x",
      })
    )
  ).toEqual({
    kind: "2fa_required",
    userId: "u",
    challenge: "c",
    method: "totp",
    verificationId: "",
    defaultFactor: {
      id: "f",
      method: "totp",
      is_default: false,
      phone_number: null,
      email: null,
    },
    availableFactors: [
      {
        id: "f",
        method: "totp",
        is_default: false,
        phone_number: null,
        email: null,
      },
      {
        id: "g",
        method: "sms",
        is_default: false,
        phone_number: null,
        email: null,
      },
    ],
    backupCodes: [],
    returnTo: "/x",
  })
  expect(
    readContinuation(
      err(403, "2fa_enrollment_required", {
        user_id: "u",
        requires_2fa_enrollment: true,
        allowed_methods: ["totp", "sms"],
        token_set: { access_token: "e", token_type: "Bearer", expires_in: 600 },
      })
    )
  ).toMatchObject({
    kind: "2fa_enrollment_required",
    allowedMethods: ["totp", "sms"],
    enrollmentToken: { access_token: "e" },
  })
})

it("rejects incomplete challenges and unrelated errors", () => {
  // A step-up code send is 2fa_required without a login challenge.
  expect(
    readContinuation(
      err(403, "2fa_required", { method: "email", verification_id: "x" })
    )
  ).toBeNull()
  expect(readContinuation(err(401, "invalid_credentials", {}))).toBeNull()
  expect(readContinuation(new Error("2fa_required"))).toBeNull()
})

it("reads step_up_required and narrows MFA-gated methods to 2fa", () => {
  expect(
    readStepUpRequired(
      err(403, "step_up_required", {
        step_up_methods: ["password", "Google"],
        max_age_seconds: 300,
      })
    )
  ).toEqual({
    methods: ["password", "google"],
    mfaRequired: false,
    maxAgeSeconds: 300,
    twoFactor: undefined,
  })
  expect(
    readStepUpRequired(
      err(403, "step_up_required", {
        step_up_methods: ["password", "2fa"],
        mfa_required: true,
        step_up_2fa: { methods: ["totp"] },
      })
    )
  ).toMatchObject({
    methods: ["2fa"],
    mfaRequired: true,
    twoFactor: { methods: ["totp"] },
  })
})

it("keeps only app-relative return targets", () => {
  const origin = "https://app.test"
  expect(safeReturnTo("/a?b=1#c", origin)).toBe("/a?b=1#c")
  expect(safeReturnTo("https://app.test/a", origin)).toBe("/a")
  expect(safeReturnTo("//evil.example/a", origin)).toBeNull()
  expect(safeReturnTo("https://evil.example/a", origin)).toBeNull()
  expect(safeReturnTo("/\\evil.example", origin)).toBeNull()
})
