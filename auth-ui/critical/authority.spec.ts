import { test } from "./browser"
import { expect } from "@playwright/test"
import { enrollRequired, login, open, seed } from "./browser"

test("AK-UI-08: TS contract: group role mutations and API-key/PAT ceilings use the real permission store", async ({
  page,
  request,
}) => {
  const manager = await seed(request)
  const member = await seed(request)
  const groupResponse = await request.post("/__fixture/group", {
    data: { userId: manager.id, role: "manager" },
  })
  expect(groupResponse.status()).toBe(201)
  const group = (await groupResponse.json()) as { id: string }
  const otherResponse = await request.post("/__fixture/group", { data: {} })
  expect(otherResponse.status()).toBe(201)
  const other = (await otherResponse.json()) as { id: string }
  await open(page)
  expect((await login(page, manager)).status).toBe("complete")

  const allowed = await page.evaluate(
    async (group) => ({
      me: await window.ak.client.getPermissions({ groupId: group }),
      admin: await window.ak.admin.permissions(group),
      scope: window.ak.admin.scopeKey,
    }),
    group.id
  )
  expect(allowed.me.permissions).toContain("project:records:read")
  expect(allowed.admin).toEqual(allowed.me)
  expect(allowed.scope).toContain("/api/v1")
  const membership = await page.evaluate(() =>
    window.ak.client.request<{
      data: { group: { id: string }; role: string }[]
    }>("GET", "/me/groups")
  )
  expect(
    membership.data.some(
      (entry) => entry.group.id === group.id && entry.role === "project:manager"
    )
  ).toBe(true)
  const forbidden = await page.evaluate(async (group) => {
    try {
      await window.ak.admin.listMembers(group)
      return null
    } catch (error) {
      return (error as { status: number }).status
    }
  }, other.id)
  expect(forbidden).toBe(403)
  const declared = await page.evaluate(
    (group) => window.ak.admin.listRoles(group),
    group.id
  )
  expect(
    declared.some(
      (role) =>
        role.name === "project:viewer" &&
        role.permissions.includes("project:records:read")
    )
  ).toBe(true)
  const custom = await page.evaluate(
    (group) =>
      window.ak.admin.createRole(group, {
        name: "critical",
        permissions: ["project:records:read"],
      }),
    group.id
  )
  expect(custom.name).toBe("project:custom-critical")
  const changed = await page.evaluate(
    ({ group, role }) =>
      window.ak.admin.updateRole(group, role, [
        "project:records:read",
        "project:records:write",
      ]),
    { group: group.id, role: custom.name }
  )
  expect(changed.permissions.sort()).toEqual([
    "project:records:read",
    "project:records:write",
  ])
  const readBack = await page.evaluate(
    ({ group, role }) => window.ak.admin.getRole(group, role),
    { group: group.id, role: custom.name }
  )
  expect(readBack.permissions.sort()).toEqual(changed.permissions)
  await page.evaluate(
    ({ group, user, role }) => window.ak.admin.setMemberRole(group, user, role),
    { group: group.id, user: member.id, role: custom.name }
  )
  const members = await page.evaluate(
    (group) => window.ak.admin.listMembers(group),
    group.id
  )
  expect(members.data).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        subject: { kind: "user", id: member.id },
        role: custom.name,
      }),
    ])
  )
  await page.evaluate(
    ({ group, user }) => window.ak.admin.removeMember(group, user),
    { group: group.id, user: member.id }
  )
  expect(
    (
      await page.evaluate(
        (group) => window.ak.admin.listMembers(group),
        group.id
      )
    ).data.some((entry) => entry.subject.id === member.id)
  ).toBe(false)
  await page.evaluate(
    ({ group, role }) => window.ak.admin.deleteRole(group, role),
    { group: group.id, role: custom.name }
  )
  expect(
    (
      await page.evaluate((group) => window.ak.admin.listRoles(group), group.id)
    ).some((role) => role.name === custom.name)
  ).toBe(false)

  const key = await page.evaluate(
    (group) =>
      window.ak.admin.createAPIKey(group, {
        name: "critical-reader",
        role: "project:viewer",
      }),
    group.id
  )
  expect(key.api_key.group_id).toBe(group.id)
  expect(key.secret.length).toBeGreaterThan(20)
  const keys = await page.evaluate(
    (group) => window.ak.admin.listAPIKeys(group),
    group.id
  )
  expect(keys.data.some((entry) => entry.id === key.api_key.id)).toBe(true)
  expect(JSON.stringify(keys)).not.toContain(key.secret)
  const keyRead = await request.get(
    `/api/v1/me/permissions?group_id=${group.id}`,
    { headers: { Authorization: `Bearer ${key.secret}` } }
  )
  expect(keyRead.status()).toBe(200)
  expect(await keyRead.json()).toMatchObject({
    group_id: group.id,
    permissions: ["project:records:read"],
  })
  await page.evaluate(
    ({ group, id }) => window.ak.admin.revokeAPIKey(group, id),
    { group: group.id, id: key.api_key.id }
  )
  expect(
    (
      await request.get(`/api/v1/me/permissions?group_id=${group.id}`, {
        headers: { Authorization: `Bearer ${key.secret}` },
      })
    ).status()
  ).toBe(401)

  const pat = await page.evaluate(
    (group) =>
      window.ak.client.createPersonalAccessToken({
        name: "members-reader",
        group_id: group,
        permissions: ["project:members:read"],
      }),
    group.id
  )
  expect(pat.token.owner_user_id).toBe(manager.id)
  expect(pat.token.permissions).toEqual(["project:members:read"])
  const listed = await page.evaluate(() =>
    window.ak.client.listPersonalAccessTokens()
  )
  expect(listed.data.some((entry) => entry.id === pat.token.id)).toBe(true)
  expect(JSON.stringify(listed)).not.toContain(pat.secret)
  expect(
    (
      await request.get(`/api/v1/groups/${group.id}/members`, {
        headers: { Authorization: `Bearer ${pat.secret}` },
      })
    ).status()
  ).toBe(200)
  expect(
    (
      await request.get("/api/v1/me", {
        headers: { Authorization: `Bearer ${pat.secret}` },
      })
    ).status()
  ).toBe(403)
  await page.evaluate(
    (id) => window.ak.client.revokePersonalAccessToken(id),
    pat.token.id
  )
  expect(
    (
      await request.get(`/api/v1/groups/${group.id}/members`, {
        headers: { Authorization: `Bearer ${pat.secret}` },
      })
    ).status()
  ).toBe(401)
})

test("AK-UI-09: TS contract: own-session revocation preserves the caller and records the actual other session", async ({
  browser,
  page,
  request,
}) => {
  const who = await seed(request)
  await open(page)
  expect((await login(page, who)).status).toBe("complete")
  const context = await browser.newContext({
    baseURL: process.env.E2E_BASE_URL,
  })
  try {
    const other = await context.newPage()
    await open(other)
    expect((await login(other, who)).status).toBe("complete")
    const sessions = await page.evaluate(() => window.ak.client.listSessions())
    expect(sessions).toHaveLength(2)
    const otherSession = sessions.find((session) => !session.current)!
    expect(otherSession).toBeTruthy()
    await page.evaluate(
      (id) => window.ak.client.revokeSessions([id]),
      otherSession.id
    )
    expect(
      await page.evaluate(() => window.ak.client.listSessions())
    ).toHaveLength(1)
    const events = await page.evaluate(() =>
      window.ak.client.listSessionEvents({ limit: 50 })
    )
    expect(
      events.data.some(
        (event) =>
          event.kind === "session_revoked" &&
          event.session_id === otherSession.id
      )
    ).toBe(true)
    expect((await login(other, who)).status).toBe("complete")
    expect(
      await page.evaluate(() => window.ak.client.listSessions())
    ).toHaveLength(2)
    await page.evaluate(() => window.ak.client.revokeOtherSessions())
    const after = await page.evaluate(() => window.ak.client.listSessions())
    expect(after).toHaveLength(1)
    expect(after[0].current).toBe(true)
    expect(
      await page.evaluate(() =>
        window.ak.client.request("PATCH", "/me", {
          body: { preferred_language: "en" },
        })
      )
    ).toMatchObject({ id: who.id })
  } finally {
    await context.close()
  }
})

test("AK-UI-10: TS contract: administrator user lifecycle, session containment and retained event reads", async ({
  page,
  request,
  browser,
}) => {
  const operator = await seed(request, { rootRole: "operator" })
  const subject = await seed(request)
  await open(page)
  const signingIn = await login(page, operator)
  expect(signingIn.status).toBe("enrollment_required")
  if (signingIn.status !== "enrollment_required")
    throw new Error("privileged operator did not require MFA")
  await enrollRequired(page, signingIn.enrollment.token_set)
  await page.evaluate(
    (id) => window.ak.admin.setRootRole(id, "root:reader"),
    subject.id
  )
  const rootMembers = await page.evaluate(() =>
    window.ak.admin.listMembers("root")
  )
  expect(
    rootMembers.data.some(
      (entry) => entry.subject.id === subject.id && entry.role === "root:reader"
    )
  ).toBe(true)
  await page.evaluate((id) => window.ak.admin.removeRootRole(id), subject.id)
  const context = await browser.newContext({
    baseURL: process.env.E2E_BASE_URL,
  })
  try {
    const target = await context.newPage()
    await open(target)
    expect((await login(target, subject)).status).toBe("complete")
    expect(
      await page.evaluate(
        (id) => window.ak.admin.listUserSessions(id),
        subject.id
      )
    ).toHaveLength(1)
    await page.evaluate(
      (id) => window.ak.admin.revokeUserSessions(id),
      subject.id
    )
    expect(
      await page.evaluate(
        (id) => window.ak.admin.listUserSessions(id),
        subject.id
      )
    ).toEqual([])
    const history = await page.evaluate(
      (id) => window.ak.admin.listUserSessionEvents(id, { limit: 50 }),
      subject.id
    )
    expect(
      history.data.some((event) => event.kind === "account_sessions_revoked")
    ).toBe(true)
    await page.evaluate(
      (id) => window.ak.admin.banUser(id, { reason: "critical fixture" }),
      subject.id
    )
    const ban = await target.evaluate(async (who) => {
      try {
        return {
          result: await window.ak.client.signInWithPassword({
            identifier: who.email,
            password: who.password,
          }),
        }
      } catch (error) {
        return { status: (error as { status: number }).status }
      }
    }, subject)
    expect(ban.status).toBe(401)
    await page.evaluate((id) => window.ak.admin.unbanUser(id), subject.id)
    expect((await login(target, subject)).status).toBe("complete")
    await page.evaluate((id) => window.ak.admin.deleteUser(id), subject.id)
    const deleted = await target.evaluate(async (who) => {
      try {
        await window.ak.client.signInWithPassword({
          identifier: who.email,
          password: who.password,
        })
        return null
      } catch (error) {
        return (error as { code: string }).code
      }
    }, subject)
    expect(deleted).toBe("account_disabled")
    await page.evaluate((id) => window.ak.admin.restoreUser(id), subject.id)
    expect((await login(target, subject)).status).toBe("complete")
    const log = await page.evaluate(() =>
      window.ak.client.listEvents({ limit: 100 })
    )
    expect(log.events.length).toBeGreaterThan(0)
  } finally {
    await context.close()
  }
})
