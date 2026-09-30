// Every AuthKit route the client calls must be in the generated route catalog.
import { expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AUTHKIT_ROUTES } from "./generated/routes.ts"
import { complete } from "./testing.ts"

const routes = AUTHKIT_ROUTES.map(({ method, path }) => ({
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
  await client.completeSignIn(async () => complete("u1"))
  const calls: (() => Promise<unknown>)[] = [
    () => client.getCapabilities(),
    () => client.signInWithPassword({ identifier: "a", password: "b" }),
    () => client.register({ identifier: "a", username: "u", password: "p" }),
    () => client.checkAvailability({ username: "u" }),
    () => client.abandonRegistration({ identifier: "a", password: "p" }),
    () => client.requestVerification({ identifier: "a" }),
    () => client.confirmVerification({ identifier: "a", code: "c" }),
    () => client.changeEmail("a@b.c"),
    () => client.changePhone("+15550100"),
    () => client.removePhone(),
    () => client.requestPasswordReset("a"),
    () => client.confirmPasswordReset({ token: "t", newPassword: "p" }),
    () => client.changePassword({ newPassword: "p" }),
    () => client.verifyTwoFactor({ userId: "u", challenge: "c", code: "1" }),
    () => client.sendTwoFactorChallenge({ userId: "u", challenge: "c" }),
    () => client.getTwoFactor(),
    () => client.setupTwoFactor({ method: "totp" }),
    () => client.addTwoFactorFactor({ method: "totp", code: "1" }),
    () => client.setDefaultTwoFactorFactor("f"),
    () => client.removeTwoFactorFactor("f"),
    () => client.disableTwoFactor(),
    () => client.regenerateBackupCodes(),
    () => client.getSecurity(),
    () => client.stepUpWithPassword("p"),
    () => client.sendStepUpCode(),
    () => client.stepUpWithTwoFactor({ code: "1" }),
    () => client.startOidcStepUp("google", "/"),
    () => client.startProviderLink("google"),
    () => client.unlinkProvider("google"),
    () => client.listSessions(),
    () => client.revokeSessions(["s1"]),
    () => client.revokeOtherSessions(),
    () => client.listSessionEvents({ kind: ["session_created"] }),
    () => client.listSignInKeys(),
    () => client.renameSignInKey("k", "laptop"),
    () => client.revokeSignInKey("k"),
    () => client.registerPasskey(),
    () => client.getMe(),
    () => client.updateProfile({ username: "u" }),
    () => client.getPermissions(),
    () => client.redeemInvitation("c"),
    () => client.confirmAccountRecovery("t"),
    () => client.startPasswordless({ identifier: "a", inviteCode: "i" }),
    () => client.confirmPasswordless({ identifier: "a", code: "c" }),
    () => client.linkSolanaWallet({}),
    () => client.refresh(),
    () => client.deleteAccount(),
    () => client.completeSignIn(async () => complete("u1")),
    () => client.completeRedirect("#code=c&state=s"),
    () => client.signOut(),
    () => client.oidcLoginStart("google", { inviteCode: "i" }),
  ]
  for (const call of calls) await call().catch(() => undefined)
  called.add(`GET ${client.oidcLoginUrl("google").split("?")[0]}`)

  const missing = [...called].filter((c) => {
    const [method, path] = c.split(" ")
    return !inCatalog(method, path)
  })
  expect(missing).toEqual([])
  expect(called.size).toBeGreaterThanOrEqual(51)
})
