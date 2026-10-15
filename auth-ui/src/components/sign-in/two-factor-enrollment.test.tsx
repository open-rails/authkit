// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import type { TwoFactorMethod } from "../../client/types.ts"
import { authResult, json, stubFetch, tokenSet } from "../../client/testing.ts"
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

async function renderEnrollment(methods: TwoFactorMethod[]) {
  const requested: unknown[] = []
  const fetch = stubFetch({
    "GET /api/v1/capabilities": () =>
      json(200, {
        registration: { mode: "open", invite_token_required: false },
        external_login_providers: [],
        password: {},
        passwordless: { enabled: false },
        passkeys: { login: false },
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
  return { user, requested }
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
