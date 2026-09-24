// Every AuthKit route the client calls must be in the pinned route catalog.
import { expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import contract from "./generated/authkit-contract.json"
import { jwt } from "./testing.ts"

const routes = contract.routes.map(({ method, path }) => ({
  method,
  pattern: new RegExp(`^${path.replace(/\{[^}]+\}/g, "[^/]+")}$`),
}))

const inCatalog = (method: string, path: string) =>
  routes.some((r) => r.method === method && r.pattern.test(path))

it("calls only routes AuthKit mounts", async () => {
  const called = new Set<string>()
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    called.add(`${init?.method ?? "GET"} ${String(input).split("?")[0]}`)
    return new Response(null, { status: 204 })
  })
  const client = createAuthClient({ fetch })
  await client.completeSignIn(async () => ({ access_token: jwt("u1") }))
  const calls: (() => Promise<unknown>)[] = [
    () => client.getCapabilities(),
    () => client.signInWithPassword({ identifier: "a", password: "b" }),
    () => client.register({ identifier: "a", username: "u", password: "p" }),
    () => client.checkAvailability({ username: "u" }),
    () => client.resendRegistration("a"),
    () => client.abandonRegistration({ identifier: "a", password: "p" }),
    () => client.requestVerification({ identifier: "a" }),
    () => client.confirmVerification({ identifier: "a", code: "c" }),
    () => client.requestPasswordReset("a"),
    () => client.confirmPasswordReset({ token: "t", newPassword: "p" }),
    () => client.changePassword({ newPassword: "p" }),
    () => client.verifyTwoFactor({ userId: "u", challenge: "c", code: "1" }),
    () => client.sendTwoFactorChallenge({ userId: "u", challenge: "c" }),
    () => client.getTwoFactor(),
    () => client.enableTwoFactor({ method: "totp" }),
    () => client.disableTwoFactor({ factorId: "f" }),
    () => client.regenerateBackupCodes(),
    () => client.stepUpWithPassword("p"),
    () => client.stepUpWithTwoFactor(),
    () => client.startOidcStepUp("google", "/"),
    () => client.startProviderLink("google"),
    () => client.unlinkProvider("google"),
    () => client.listSessions(),
    () => client.revokeSessions(["s1"]),
    () => client.getMe(),
    () => client.getPermissions(),
    () => client.updateUsername("u"),
    () => client.updatePreferredLanguage("en"),
    () => client.confirmAccountRecovery("t"),
    () => client.refresh(),
    () => client.revokeAllSessions(),
    () => client.completeSignIn(async () => ({ access_token: jwt("u1") })),
    () => client.deleteAccount(),
    () => client.completeSignIn(async () => ({ access_token: jwt("u1") })),
    () => client.signOut(),
    () => client.oidcLoginStart("google", { accountInviteToken: "i" }),
  ]
  for (const call of calls) await call().catch(() => undefined)
  called.add(`GET ${client.oidcLoginUrl("google").split("?")[0]}`)

  const missing = [...called].filter((c) => {
    const [method, path] = c.split(" ")
    return !inCatalog(method, path)
  })
  expect(missing).toEqual([])
  expect(called.size).toBeGreaterThanOrEqual(35)
})
