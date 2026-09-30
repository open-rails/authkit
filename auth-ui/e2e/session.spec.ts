import { expect, test } from "@playwright/test"

import { accessToken, api, outbox } from "./support/api"

test("register, verify, login, refresh via cookie, logout", async ({
  page,
  request,
  context,
}) => {
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `e2e-${id}@example.test`
  const password = "Correct-horse-battery-9"
  await page.goto("/")

  const reg = await api(page, "POST", "/register", {
    identifier: email,
    username: `u${id}`,
    password,
  })
  // A code went to the address: 202, no body, no session.
  expect(reg.status, JSON.stringify(reg.body)).toBe(202)
  expect(reg.body).toBeNull()

  const code = (await outbox(request, email)).find(
    (m) => m.kind === "verification"
  )?.code
  expect(code).toBeTruthy()

  const verified = await api(page, "POST", "/verify/confirm", {
    identifier: email,
    code,
  })
  expect(verified.status, JSON.stringify(verified.body)).toBe(200)
  expect(verified.body).toMatchObject({
    status: "complete",
    user: { email },
    token_set: { token_type: "Bearer" },
  })

  const login = await api(page, "POST", "/password/login", {
    identifier: email,
    password,
  })
  expect(login.status, JSON.stringify(login.body)).toBe(200)
  expect(login.body).toMatchObject({
    status: "complete",
    token_set: { token_type: "Bearer", refresh_token: null },
    user: { email },
  })
  const access = accessToken(login)

  const cookie = (await context.cookies()).find((c) => c.name === "authkit_rt")
  expect(cookie).toMatchObject({
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
  })

  const me = await api(page, "GET", "/me", undefined, access)
  expect(me.status).toBe(200)
  expect(me.body).toMatchObject({ email })

  const refreshed = await api(page, "POST", "/token", {
    grant_type: "refresh_token",
  })
  expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200)
  expect(refreshed.body).toMatchObject({
    status: "complete",
    token_set: { refresh_token: null },
  })
  const access2 = accessToken(refreshed)
  const rotated = (await context.cookies()).find((c) => c.name === "authkit_rt")
  expect(rotated?.value).not.toBe(cookie!.value)

  const logout = await api(page, "DELETE", "/logout", undefined, access2)
  expect(logout.status).toBe(204)
  expect(
    (await context.cookies()).find((c) => c.name === "authkit_rt")
  ).toBeUndefined()

  const afterLogout = await api(page, "POST", "/token", {
    grant_type: "refresh_token",
  })
  expect(afterLogout.status).toBe(401)
  expect(afterLogout.body).toMatchObject({ error: { code: "no_session" } })
})
