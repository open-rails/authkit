import { test } from "./browser"
import { expect } from "@playwright/test"
import { identity, login, open, register, seed } from "./browser"

test("AK-J29-C01: start, stop, subscribe and browser restore retain only the current identity", async ({
  page,
  request,
}) => {
  const who = await seed(request)
  await open(page)
  const capabilities = await page.evaluate(() =>
    window.ak.client.getCapabilities()
  )
  expect(capabilities.verification.registration).toBe("required")
  expect(capabilities.two_factor.mode).toBe("optional")
  expect(capabilities.channels).toMatchObject({ email: true, sms: true })
  const result = await login(page, who)
  expect(result.status).toBe("complete")
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
  const hint = await page.evaluate((who) => {
    window.ak.client.rememberUsername(who.id, who.username.toUpperCase())
    window.ak.client.rememberUsername(
      "00000000-0000-4000-8000-000000000099",
      "foreign"
    )
    return JSON.parse(localStorage.getItem("authkit:session:/api/v1")!) as {
      userId: string
      username: string
    }
  }, who)
  expect(hint).toMatchObject({ userId: who.id, username: who.username })
  const state = await page.evaluate(async () => {
    const stop = window.ak.client.start()
    const refreshed = await window.ak.client.refresh()
    stop()
    window.ak.client.stop()
    window.ak.client.start()
    await window.ak.client.ready()
    return { refreshed, status: window.ak.client.getSnapshot().status }
  })
  expect(state.refreshed).toBe(true)
  expect(
    await page.evaluate(() =>
      window.ak.events.some((event) => event.status === "authenticated")
    )
  ).toBe(true)
  expect(state.status).toBe("authenticated")
  const cookies = await page.context().cookies()
  expect(
    cookies.some((cookie) => cookie.httpOnly && cookie.value.length > 20)
  ).toBe(true)
  await page.reload()
  await expect(page.getByTestId("session-status")).toHaveText("authenticated")
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
  expect(
    await page.evaluate(() =>
      window.ak.events.filter((event) => event.kind === "registered")
    )
  ).toEqual([])
  const afterUnsubscribe = await page.evaluate(async () => {
    let observations = 0
    const unsubscribe = window.ak.client.subscribe(() => observations++)
    unsubscribe()
    await window.ak.client.signOut()
    return observations
  })
  expect(afterUnsubscribe).toBe(0)
  await page.reload()
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
})

test("AK-J29-C04: registration callback follows real contact proof and does not replay on refresh", async ({
  page,
  request,
}) => {
  await open(page)
  const who = await register(page, request)
  expect(
    await page.evaluate(() =>
      window.ak.events.filter((event) => event.kind === "registered")
    )
  ).toEqual([
    {
      kind: "registered",
      userId: who.id,
      status: "authenticated",
      hasAccessToken: true,
    },
  ])
  const order = await page.evaluate(() => window.ak.events)
  const registration = order.findIndex((event) => event.kind === "registered")
  expect(
    order
      .slice(registration + 1)
      .some((event) => event.status === "authenticated")
  ).toBe(true)
  await page.evaluate(() => window.ak.client.refresh())
  expect(
    await page.evaluate(() =>
      window.ak.events.filter((event) => event.kind === "registered")
    )
  ).toHaveLength(1)
  await page.evaluate(() => window.ak.client.signOut())
  expect((await login(page, who)).status).toBe("complete")
  expect(
    await page.evaluate(() =>
      window.ak.events.filter((event) => event.kind === "registered")
    )
  ).toHaveLength(1)
})

test("AK-J29-C02: concurrent refresh coalesces and a real network outage preserves the account", async ({
  page,
  request,
}) => {
  const who = await seed(request)
  await page.clock.install()
  await open(page)
  expect((await login(page, who)).status).toBe("complete")
  let refreshRequests = 0
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/api/v1/token"
    )
      refreshRequests++
  })
  const refreshed = await page.evaluate(() =>
    Promise.all([
      window.ak.client.refresh(),
      window.ak.client.refresh(),
      window.ak.client.refresh(),
    ])
  )
  expect(refreshed).toEqual([true, true, true])
  expect(refreshRequests).toBe(1)
  await page.context().setOffline(true)
  try {
    const offline = await page.evaluate(async () => {
      let failure: string | undefined
      try {
        await window.ak.client.authFetch("/api/v1/me", { cache: "no-store" })
      } catch (error) {
        failure = window.ak.transportFailure(error)
      }
      const refreshed = await window.ak.client.refresh()
      const snapshot = window.ak.client.getSnapshot()
      return {
        failure,
        refreshed,
        status: snapshot.status,
        userId: snapshot.status === "authenticated" ? snapshot.userId : null,
      }
    })
    expect(offline).toEqual({
      failure: "network_error",
      refreshed: false,
      status: "authenticated",
      userId: who.id,
    })
  } finally {
    await page.context().setOffline(false)
  }
  // Reconnection does not erase the documented client retry backoff. Drive
  // browser time instead of sleeping or weakening that protection.
  expect(await page.evaluate(() => window.ak.client.refresh())).toBe(false)
  await page.clock.fastForward(5_001)
  expect(await page.evaluate(() => window.ak.client.refresh())).toBe(true)
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
})

test("AK-J29-C03: a delayed real profile response cannot cross logout and account switch", async ({
  page,
  request,
}) => {
  const first = await seed(request)
  const next = await seed(request)
  await open(page)
  let arrive!: (value: { status: number; id: string }) => void
  let release!: () => void
  let complete!: () => void
  const captured = new Promise<{ status: number; id: string }>((resolve) => {
    arrive = resolve
  })
  const released = new Promise<void>((resolve) => {
    release = resolve
  })
  const settled = new Promise<void>((resolve) => {
    complete = resolve
  })
  let held = false
  await page.route("**/api/v1/me", async (route) => {
    if (held || route.request().method() !== "GET") {
      await route.continue()
      return
    }
    held = true
    const response = await route.fetch()
    const body = (await response.json()) as { id: string }
    arrive({ status: response.status(), id: body.id })
    await released
    try {
      await route.fulfill({ response })
    } catch (error) {
      if (!route.request().failure()?.errorText.includes("ERR_ABORTED"))
        throw error
    } finally {
      complete()
    }
  })
  try {
    expect((await login(page, first)).status).toBe("complete")
    expect(await captured).toEqual({ status: 200, id: first.id })
    await page.evaluate(() => window.ak.client.signOut())
    expect((await login(page, next)).status).toBe("complete")
    await expect(page.getByTestId("profile-email")).toHaveText(next.email)
  } finally {
    release()
  }
  await settled
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()))
      )
  )
  await expect(page.getByTestId("session-user")).toHaveText(next.id)
  await expect(page.getByTestId("profile-email")).toHaveText(next.email)
  await expect(page.getByText(first.email, { exact: true })).toHaveCount(0)
  const crossed = await page.evaluate(
    ({ current, previous }) =>
      window.ak.events.some(
        (event) =>
          event.kind === "profile" &&
          event.userId === current &&
          event.profileUserId === previous
      ),
    { current: next.id, previous: first.id }
  )
  expect(crossed).toBe(false)
})

test("AK-J29-C06: real auth errors, rate limits and abort preserve their public meaning", async ({
  page,
  request,
}) => {
  await open(page, "?limited")
  const limited = await page.evaluate(async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      // Capabilities are legitimately cacheable; force real network I/O to
      // exercise the actual service limiter rather than a cached200.
      const response = await window.ak.client.authFetch(
        "/limited/api/v1/capabilities",
        { cache: "no-store" }
      )
      if (response.status === 429) {
        const error = await window.ak.readAuthKitError(response)
        return {
          status: error.status,
          code: error.code,
          retry: error.retryAfterSeconds,
        }
      }
      if (response.status !== 200)
        throw new Error(`unexpected capabilities response ${response.status}`)
    }
    return null
  })
  expect(limited).toMatchObject({ status: 429, code: "rate_limited" })
  expect(limited!.retry).toBeGreaterThan(0)
  expect(limited!.retry).toBeLessThanOrEqual(60)

  const who = await seed(request)
  await open(page)
  const denied = await page.evaluate(async ({ email }) => {
    try {
      await window.ak.client.signInWithPassword({
        identifier: email,
        password: "Wrong-only-in-this-test-99",
      })
      return null
    } catch (error) {
      const e = error as { status: number; code: string; message: string }
      return {
        status: e.status,
        code: e.code,
        leaksPassword: e.message.includes("Wrong-only-in-this-test-99"),
      }
    }
  }, who)
  expect(denied).toEqual({
    status: 401,
    code: "invalid_credentials",
    leaksPassword: false,
  })
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
  expect((await login(page, who)).status).toBe("complete")
  const aborted = await page.evaluate(async () => {
    const controller = new AbortController()
    controller.abort()
    try {
      await window.ak.client.getCapabilities(controller.signal)
      return null
    } catch (error) {
      return {
        name: (error as Error).name,
        status: window.ak.client.getSnapshot().status,
      }
    }
  })
  expect(aborted).toEqual({ name: "AbortError", status: "authenticated" })
  const snapshot = await page.evaluate(() => window.ak.client.getSnapshot())
  expect(snapshot.status).toBe("authenticated")
  expect(snapshot).not.toHaveProperty("refreshToken")
  expect(snapshot).not.toHaveProperty("refresh_token")
  expect(snapshot).not.toHaveProperty("privateKey")
  expect(await page.evaluate(() => document.cookie)).not.toContain("refresh")
})

test("AK-J29-C04: contact proof cannot replay a mutation across a replacement sign-in", async ({
  page,
}) => {
  const who = identity()
  await open(page, "?unproved")
  const signIn = await page.evaluate(
    (who) =>
      window.ak.client.register({
        identifier: who.email,
        username: who.username,
        password: who.password,
      }),
    who
  )
  expect(signIn?.status).toBe("complete")
  const result = await page.evaluate(async () => {
    const seen: { identifier: string; channel: string }[] = []
    const unregister = window.ak.client.onContactProofRequired(
      async (proof) => {
        seen.push(proof)
        await window.ak.client.requestVerification({
          identifier: proof.identifier,
        })
        const response = await fetch(
          `/__fixture/deliveries?profile=unproved&to=${encodeURIComponent(proof.identifier)}`,
          { cache: "no-store" }
        )
        const messages = (await response.json()) as { code?: string }[]
        const delivered = messages.findLast((message) => !!message.code)?.code
        if (!delivered)
          throw new Error("real sender did not deliver the requested proof")
        // This host deliberately finishes the delivered proof as a fresh
        // sign-in. It uses the real endpoint, with no canned AuthResult.
        await window.ak.client.completeSignIn(() =>
          window.ak.client.request("POST", "/verify/confirm", {
            bearer: null,
            body: { identifier: proof.identifier, code: delivered },
          })
        )
        return true
      }
    )
    try {
      let replaced: string | undefined
      try {
        await window.ak.client.setupTwoFactor({ method: "totp" })
      } catch (error) {
        replaced = (error as Error).name
      }
      // The real proof retires pre-proof credentials and creates a new
      // sign-in. An explicit new action is required; never weaken the
      // client's generation guard to resume an old mutation automatically.
      const setup = await window.ak.client.setupTwoFactor({ method: "totp" })
      return {
        replaced,
        seen,
        method: setup.method,
        hasSecret: !!setup.secret,
        snapshot: window.ak.client.getSnapshot().status,
      }
    } finally {
      unregister()
    }
  })
  expect(result).toEqual({
    replaced: "AuthSessionChangedError",
    seen: [{ identifier: who.email, channel: "email" }],
    method: "totp",
    hasSecret: true,
    snapshot: "authenticated",
  })
})
