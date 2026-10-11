import { expect, it } from "vitest"

import { registrationAvailable, registrationMode } from "./registration.ts"

const caps = (mode: string) => ({
  registration: {
    mode,
    invite_token_required: mode === "invite_only",
    agreements: [],
  },
})

it("reads the advertised mode, unknown values as closed", () => {
  expect(registrationMode(null)).toBeNull()
  expect(registrationMode(undefined)).toBeNull()
  expect(registrationMode(caps("open"))).toBe("open")
  expect(registrationMode(caps("invite_only"))).toBe("invite_only")
  expect(registrationMode(caps("closed"))).toBe("closed")
  expect(registrationMode(caps("waitlist"))).toBe("closed")
})

it("offers sign-up only when the policy lets this visitor in", () => {
  expect(registrationAvailable(null)).toBe(false)
  expect(registrationAvailable(caps("open"))).toBe(true)
  expect(registrationAvailable(caps("closed"), "inv-1")).toBe(false)
  expect(registrationAvailable(caps("invite_only"))).toBe(false)
  expect(registrationAvailable(caps("invite_only"), "  ")).toBe(false)
  expect(registrationAvailable(caps("invite_only"), "inv-1")).toBe(true)
})
