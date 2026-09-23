import { createHmac } from "node:crypto"

import { expect, type APIRequestContext, type Page } from "@playwright/test"

export type Reply = { status: number; body: Record<string, unknown> | null }

// Browser-side same-origin fetch, as the client library will issue it.
export function api(
  page: Page,
  method: string,
  path: string,
  body?: unknown,
  token?: string
): Promise<Reply> {
  return page.evaluate(
    async ({ method, path, body, token }) => {
      const headers: Record<string, string> = {}
      if (body !== undefined) headers["Content-Type"] = "application/json"
      if (token) headers.Authorization = `Bearer ${token}`
      const res = await fetch(`/api/v1${path}`, {
        method,
        headers,
        credentials: "same-origin",
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await res.text()
      return { status: res.status, body: text ? JSON.parse(text) : null }
    },
    { method, path, body, token }
  )
}

export type Outbox = { kind: string; code?: string; link?: string }[]

export async function outbox(
  request: APIRequestContext,
  to: string
): Promise<Outbox> {
  return (
    await request.get(`/__test/outbox?to=${encodeURIComponent(to)}`)
  ).json()
}

// Registers and verifies a fresh email account; the page must be on the app origin.
export async function registerVerified(page: Page, request: APIRequestContext) {
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `e2e-${id}@example.test`
  const password = "Correct-horse-battery-9"
  const reg = await api(page, "POST", "/register", {
    identifier: email,
    username: `u${id}`,
    password,
  })
  expect(reg.status, JSON.stringify(reg.body)).toBe(202)
  const code = (await outbox(request, email)).find(
    (m) => m.kind === "verification"
  )?.code
  const verified = await api(page, "POST", "/verify/confirm", {
    identifier: email,
    code,
  })
  expect(verified.status, JSON.stringify(verified.body)).toBe(200)
  return { email, password, access: verified.body!.access_token as string }
}

// RFC 6238 SHA-1, 6 digits, 30s step.
export function totp(secretBase32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const ch of secretBase32.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0")
  }
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)))
  const mac = createHmac("sha1", key).update(counter).digest()
  const offset = mac[mac.length - 1] & 0xf
  const n = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000
  return n.toString().padStart(6, "0")
}
