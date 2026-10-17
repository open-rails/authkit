// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import type { TwoFactorMethod } from "../../client/types.ts"
import {
  authResult,
  complete,
  json,
  stubFetch,
  stubPasskey,
  tokenSet,
} from "../../client/testing.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { useLogin } from "../../react/useLogin.ts"
import { TwoFactorEnrollment } from "./TwoFactorEnrollment.tsx"

// input-otp probes password-manager overlays; jsdom has no hit testing.
document.elementFromPoint ??= () => null

function Enrollment() {
  const controller = useLogin()
  return (
    <>
      <button
        onClick={() =>
          void controller.signIn({
            identifier: "reader@example.test",
            password: "pw",
          })
        }
      >
        Sign in
      </button>
      {controller.state.step === "enrollment" && (
        <TwoFactorEnrollment controller={controller} />
      )}
    </>
  )
}

async function renderEnrollment(methods: TwoFactorMethod[], passkeys = false) {
  const requested: unknown[] = []
  const keyRequests: { path: string; bearer: string | null }[] = []
  const fetch = stubFetch({
    "GET /api/v1/capabilities": () =>
      json(200, {
        registration: { mode: "open", invite_token_required: false },
        external_login_providers: [],
        password: {},
        passwordless: { enabled: false },
        passkeys: { login: passkeys },
        solana: { login: false },
        verification: { registration: "required" },
      }),
    "POST /api/v1/password/login": () =>
      json(
        200,
        authResult("enrollment_required", {
          enrollment: {
            token_set: tokenSet("enrollment"),
            allowed_methods: methods,
          },
        })
      ),
    "POST /api/v1/me/passkeys/enroll/begin": (request) => {
      keyRequests.push({
        path: "begin",
        bearer: new Headers(request.headers).get("Authorization"),
      })
      return json(200, {
        publicKey: {
          challenge: "AQID",
          rp: { id: "x.test", name: "X" },
          user: { id: "AQI", name: "reader", displayName: "Reader" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required" },
        },
      })
    },
    "POST /api/v1/me/passkeys/enroll/finish": (request) => {
      keyRequests.push({
        path: "finish",
        bearer: new Headers(request.headers).get("Authorization"),
      })
      return json(200, complete("u1"))
    },
    "POST /api/v1/me/2fa/setup": (request) => {
      requested.push(JSON.parse(String(request.body)))
      return json(200, {
        method: "totp",
        secret: "JBSWY3DPEHPK3PXP",
        otpauth_uri: "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP",
      })
    },
  })
  const client = createAuthClient({ fetch, sessionHint: false })
  render(
    <AuthProvider client={client} autoStart={false}>
      <AuthUiProvider>
        <Enrollment />
      </AuthUiProvider>
    </AuthProvider>
  )
  const user = userEvent.setup()
  await user.click(screen.getByRole("button", { name: "Sign in" }))
  await screen.findByRole("heading", {
    name: "Set up two-factor authentication",
  })
  return { user, requested, keyRequests, client }
}

describe("required two-factor enrollment", () => {
  it("offers only authenticator and SMS and never sends email enrollment", async () => {
    const { user, requested } = await renderEnrollment(["email", "sms", "totp"])
    expect(
      screen.queryByRole("radio", { name: /email/i })
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole("radio", { name: /Authenticator app/ })
    ).toBeChecked()
    expect(screen.getByRole("radio", { name: /SMS/ })).toBeInTheDocument()
    expect(requested).toEqual([])
    await user.click(
      screen.getByRole("button", { name: "Set up authenticator" })
    )
    await screen.findByRole("button", { name: "Show manual setup key" })
    expect(screen.queryByText("JBSWY3DPEHPK3PXP")).not.toBeInTheDocument()
    expect(requested).toEqual([{ method: "totp" }])
  })

  it("shows an unavailable-method notice instead of enrolling email", async () => {
    const { requested } = await renderEnrollment(["email"])
    expect(screen.getByRole("alert")).toBeInTheDocument()
    expect(screen.queryByRole("radio")).not.toBeInTheDocument()
    expect(
      screen.queryByRole("button", { name: "Send code" })
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("button", { name: "Set up authenticator" })
    ).not.toBeInTheDocument()
    expect(requested).toEqual([])
  })
})

it("offers a passkey/security key even without code methods and completes without requesting OTP", async () => {
  stubPasskey()
  const create = vi.fn(async (options: CredentialCreationOptions) => {
    expect(options.publicKey?.authenticatorSelection?.userVerification).toBe(
      "required"
    )
    const Credential =
      globalThis.PublicKeyCredential as unknown as new () => object
    return Object.assign(new Credential(), {
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        attestationObject: new Uint8Array([2]).buffer,
        getTransports: () => ["usb"],
      },
    })
  })
  create.mockRejectedValueOnce(new DOMException("dismissed", "NotAllowedError"))
  Object.assign(navigator.credentials, { create })
  const { user, requested, keyRequests, client } = await renderEnrollment(
    [],
    true
  )
  const button = await screen.findByRole("button", {
    name: "Set up a passkey or security key",
  })
  expect(screen.queryByRole("alert")).toBeNull()
  expect(screen.queryByRole("radio")).toBeNull()
  await user.click(button)
  await waitFor(() => expect(create).toHaveBeenCalledOnce())
  expect(screen.queryByRole("alert")).toBeNull()
  await user.click(button)
  await waitFor(() =>
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  )
  expect(requested).toEqual([])
  expect(keyRequests.map((request) => request.path)).toEqual([
    "begin",
    "begin",
    "finish",
  ])
  expect(
    keyRequests.every(
      (request) =>
        request.bearer === `Bearer ${tokenSet("enrollment").access_token}`
    )
  ).toBe(true)
  expect(create.mock.calls.at(-1)?.[0]).toMatchObject({
    publicKey: { authenticatorSelection: { userVerification: "required" } },
  })
})
