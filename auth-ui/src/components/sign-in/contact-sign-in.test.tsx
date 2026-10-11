// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import {
  authError,
  json,
  passkeyAssertion,
  passkeyOptions,
  stubFetch,
  stubPasskey,
} from "../../client/testing.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { signedIn } from "../../react/testing.tsx"
import { ContactSignIn } from "./ContactSignIn.tsx"

document.elementFromPoint ??= () => null

const terms = {
  key: "network-terms",
  version: "2026-10-10",
  url: "https://openrails.test/terms",
}
const privacy = {
  key: "privacy",
  version: "2026-10-10",
  url: "https://openrails.test/privacy",
}

const capabilities =
  (passkeys = false) =>
  () =>
    json(200, {
      registration: {
        mode: "open",
        invite_token_required: false,
        agreements: [terms.key, privacy.key],
      },
      external_login_providers: [],
      password: {},
      passwordless: { enabled: true, channels: ["email", "sms"] },
      passkeys: { login: passkeys },
      solana: { login: false },
      verification: { registration: "none" },
      agreements: [terms, privacy],
      sms: { countries: ["US", "CA"] },
    })

function renderUi(ui: ReactNode, fetch: typeof globalThis.fetch) {
  const client = createAuthClient({ fetch })
  render(
    <AuthProvider client={client} autoStart={false}>
      <AuthUiProvider>{ui}</AuthUiProvider>
    </AuthProvider>
  )
  return client
}

const bodies = (fetch: ReturnType<typeof stubFetch>, route: string) =>
  fetch.mock.calls
    .filter(([url]) => String(url).endsWith(route))
    .map(([, init]) => JSON.parse(String(init?.body)))

describe("ContactSignIn", () => {
  it("signs up with an emailed code once the agreements are accepted", async () => {
    const user = userEvent.setup()
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities(),
      "POST /api/v1/passwordless/start": [new Response(null, { status: 202 })],
      "POST /api/v1/passwordless/confirm": [
        authError(409, "agreement_required", { agreements: [terms, privacy] }),
        json(200, signedIn({ sub: "u1", sid: "s1" }, { created: true })),
      ],
    })
    renderUi(<ContactSignIn onSignedIn={onSignedIn} />, fetch)

    await user.type(
      await screen.findByLabelText("Email or phone number"),
      "shopper@x.test"
    )
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await screen.findByRole("heading", { name: "Enter your code" })
    expect(screen.getByText(/shopper@x.test/)).toBeVisible()
    await user.type(screen.getByLabelText("Verification code"), "123456")

    await screen.findByRole("heading", { name: "Create your account" })
    expect(screen.getByRole("link", { name: "Network terms" })).toHaveAttribute(
      "href",
      terms.url
    )
    const create = screen.getByRole("button", { name: "Create account" })
    expect(create).toBeDisabled()
    await user.click(screen.getByRole("checkbox"))
    await user.click(create)

    await waitFor(() => expect(onSignedIn).toHaveBeenCalledOnce())
    expect(bodies(fetch, "/passwordless/start")).toEqual([
      { identifier: "shopper@x.test", mode: "code" },
    ])
    expect(bodies(fetch, "/passwordless/confirm")).toEqual([
      { identifier: "shopper@x.test", code: "123456" },
      {
        identifier: "shopper@x.test",
        code: "123456",
        agreements: [
          { key: terms.key, version: terms.version },
          { key: privacy.key, version: privacy.version },
        ],
      },
    ])
  })

  it("sends a phone number in E.164 and signs straight in", async () => {
    const user = userEvent.setup()
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities(),
      "POST /api/v1/passwordless/start": [new Response(null, { status: 202 })],
      "POST /api/v1/passwordless/confirm": [
        json(200, signedIn({ sub: "u2", sid: "s2" })),
      ],
    })
    renderUi(
      <ContactSignIn onSignedIn={onSignedIn} defaultPhoneCountry="US" />,
      fetch
    )
    await user.type(
      await screen.findByLabelText("Email or phone number"),
      "(415) 555-0100"
    )
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await user.type(await screen.findByLabelText("Verification code"), "654321")
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledOnce())
    expect(bodies(fetch, "/passwordless/start")[0].identifier).toBe(
      "+14155550100"
    )
  })

  it("offers a passkey after a code sign-up", async () => {
    const user = userEvent.setup()
    stubPasskey()
    const create = vi.fn(async () => {
      const bytes = (...b: number[]) => new Uint8Array(b).buffer
      const Credential =
        globalThis.PublicKeyCredential as unknown as new () => object
      return Object.assign(new Credential(), {
        response: {
          clientDataJSON: bytes(1),
          attestationObject: bytes(2),
          getTransports: () => ["internal"],
        },
      })
    })
    Object.assign(navigator.credentials, { create })
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities(true),
      "POST /api/v1/passkeys/login/begin": passkeyOptions,
      "POST /api/v1/passwordless/start": [new Response(null, { status: 202 })],
      "POST /api/v1/passwordless/confirm": [
        json(200, signedIn({ sub: "u3", sid: "s3" }, { created: true })),
      ],
      "POST /api/v1/me/passkeys/register/begin": () =>
        json(200, {
          publicKey: {
            challenge: "AQID",
            rp: { id: "x.test", name: "X" },
            user: { id: "AQI", name: "u3", displayName: "u3" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        }),
      "POST /api/v1/me/passkeys/register/finish": () =>
        json(201, { id: "pk1", kind: "passkey" }),
    })
    renderUi(<ContactSignIn onSignedIn={onSignedIn} />, fetch)
    await user.type(
      await screen.findByLabelText("Email or phone number"),
      "new@x.test"
    )
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await user.type(await screen.findByLabelText("Verification code"), "111222")
    await screen.findByRole("heading", { name: "Sign in faster next time" })
    expect(onSignedIn).not.toHaveBeenCalled()
    await user.click(screen.getByRole("button", { name: "Add a passkey" }))
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledOnce())
    expect(create).toHaveBeenCalledOnce()
  })

  it("asks for the documents a sign-in finds due", async () => {
    const user = userEvent.setup()
    const onSignedIn = vi.fn()
    const updated = { ...terms, version: "2026-11-01" }
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities(),
      "POST /api/v1/passwordless/start": [new Response(null, { status: 202 })],
      "POST /api/v1/passwordless/confirm": [
        json(
          200,
          signedIn({ sub: "u4", sid: "s4" }, { agreements_due: [updated] })
        ),
      ],
      "POST /api/v1/me/agreements": () => json(200, { accepted: [], due: [] }),
    })
    renderUi(<ContactSignIn onSignedIn={onSignedIn} />, fetch)
    await user.type(
      await screen.findByLabelText("Email or phone number"),
      "back@x.test"
    )
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await user.type(await screen.findByLabelText("Verification code"), "333444")
    await screen.findByRole("heading", { name: "Review our terms" })
    await user.click(screen.getByRole("checkbox"))
    await user.click(
      screen.getByRole("button", { name: "Accept and continue" })
    )
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledOnce())
    expect(bodies(fetch, "/me/agreements")).toEqual([
      { agreements: [{ key: updated.key, version: updated.version }] },
    ])
  })

  it("signs in with a passkey the contact field's autofill offers", async () => {
    const get = stubPasskey()
    vi.stubGlobal(
      "PublicKeyCredential",
      Object.assign(globalThis.PublicKeyCredential as object, {
        isConditionalMediationAvailable: async () => true,
      })
    )
    const onSignedIn = vi.fn()
    const finished: unknown[] = []
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities(true),
      "POST /api/v1/passkeys/login/begin": passkeyOptions,
      "POST /api/v1/passkeys/login/finish": (init) => {
        finished.push(JSON.parse(String(init.body)))
        return json(200, signedIn({ sub: "u5", sid: "s5" }))
      },
    })
    renderUi(<ContactSignIn onSignedIn={onSignedIn} />, fetch)
    expect(
      await screen.findByLabelText("Email or phone number")
    ).toHaveAttribute("autocomplete", "username webauthn")
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledOnce())
    expect(get.mock.calls[0][0]).toMatchObject({ mediation: "conditional" })
    expect(finished).toEqual([passkeyAssertion])
  })
})
