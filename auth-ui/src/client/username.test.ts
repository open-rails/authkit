import { describe, expect, it } from "vitest"
import { validateUsername } from "./username.ts"
import { createAuthClient } from "./client.ts"
import { json, stubFetch } from "./testing.ts"

const policy = {
  min_length: 4,
  max_length: 30,
  pattern: "^[A-Za-z][A-Za-z0-9_]*$",
} as Parameters<typeof validateUsername>[1]

describe("usernames", () => {
  it("validates syntax before availability including spaces and unknown patterns", () => {
    expect(validateUsername("Paul Fidika", policy)).toBe(
      "username_invalid_characters"
    )
    expect(validateUsername("Naruto001", policy)).toBeNull()
    expect(validateUsername("1Naruto", policy)).toBe(
      "username_must_start_with_letter"
    )
    expect(validateUsername("ab", policy)).toBe("username_too_short")
    expect(validateUsername("abcde", { ...policy!, pattern: "[" })).toBe(
      "invalid_username"
    )
  })
  it("uses the shared generation and validation endpoints", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "GET /api/v1/usernames/generate": () =>
          json(200, { username: "sakura007" }),
        "GET /api/v1/usernames/availability": () =>
          json(200, { available: false, error: "username_invalid_characters" }),
      }),
    })
    expect(await client.generateUsername()).toBe("sakura007")
    expect(await client.checkUsername("Paul Fidika")).toMatchObject({
      available: false,
      error: "username_invalid_characters",
    })
  })
})
