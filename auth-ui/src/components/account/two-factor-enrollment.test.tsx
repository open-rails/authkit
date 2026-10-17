// @vitest-environment jsdom
import "../../test/dom.ts"

import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import { json, stubFetch } from "../../client/testing.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { noContent, session } from "../../react/testing.tsx"
import { TwoFactorPanel } from "./two-factor-panel.tsx"

// input-otp probes password-manager overlays; jsdom has no hit testing.
document.elementFromPoint ??= () => null

type Routes = Parameters<typeof stubFetch>[0]

async function renderPanel(routes: Routes) {
  const fetch = stubFetch({
    "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
    "GET /api/v1/me": () =>
      json(200, {
        id: "u1",
        username: "reader",
        email: "reader@example.test",
        email_verified: true,
        phone_number: null,
        phone_verified: false,
        has_password: true,
        providers: [],
        entitlements: [],
        naming: {},
      }),
    "GET /api/v1/capabilities": () => json(200, {}),
    ...routes,
  })
  const client = createAuthClient({ fetch, sessionHint: false })
  render(
    <AuthProvider client={client} autoStart={false}>
      <AuthUiProvider>
        <TwoFactorPanel />
      </AuthUiProvider>
    </AuthProvider>
  )
  await act(() =>
    client.signInWithPassword({
      identifier: "reader@example.test",
      password: "pw",
    })
  )
  return userEvent.setup()
}

function security(twoFactor: Record<string, unknown>) {
  return json(200, {
    last_authenticated_at: null,
    step_up_required_for_sensitive_actions: false,
    step_up_required_in_seconds: 900,
    auth_methods: ["pwd"],
    step_up_methods: ["password"],
    two_factor: twoFactor,
  })
}

describe("new two-factor enrollment", () => {
  it("offers authenticator and SMS to a verified-email account without enrolling email", async () => {
    const requested: unknown[] = []
    const user = await renderPanel({
      "GET /api/v1/me/security": () =>
        security({
          enabled: false,
          factors: [],
          allowed_methods: ["email", "sms", "totp"],
          backup_codes_remaining: 0,
        }),
      "POST /api/v1/me/2fa/setup": (request) => {
        requested.push(JSON.parse(String(request.body)))
        return json(200, {
          method: "totp",
          secret: "JBSWY3DPEHPK3PXP",
          otpauth_uri: "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP",
        })
      },
    })
    await user.click(await screen.findByRole("button", { name: "Turn on" }))
    expect(
      screen.queryByRole("radio", { name: /email/i })
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole("radio", { name: /Authenticator app/ })
    ).toBeChecked()
    expect(screen.getByRole("radio", { name: /SMS/ })).toBeInTheDocument()
    expect(requested).toEqual([])
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await screen.findByRole("button", { name: "Show manual setup key" })
    expect(screen.queryByText("JBSWY3DPEHPK3PXP")).not.toBeInTheDocument()
    expect(requested).toEqual([{ method: "totp" }])
  })

  it("keeps an existing email factor until the user explicitly removes it", async () => {
    let removed = false
    const user = await renderPanel({
      "GET /api/v1/me/security": () =>
        security({
          enabled: !removed,
          factors: removed
            ? []
            : [
                {
                  id: "email-factor",
                  method: "email",
                  is_default: true,
                  destination: "r***@example.test",
                },
              ],
          allowed_methods: ["email", "totp"],
          backup_codes_remaining: 0,
        }),
      "DELETE /api/v1/me/2fa/factors/email-factor": () => {
        removed = true
        return noContent()
      },
    })
    expect(await screen.findByText("r***@example.test")).toBeInTheDocument()
    expect(removed).toBe(false)
    await user.click(screen.getByRole("button", { name: "Remove Email" }))
    expect(removed).toBe(false)
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Remove",
      })
    )
    await waitFor(() => expect(removed).toBe(true))
    await waitFor(() =>
      expect(screen.queryByText("r***@example.test")).not.toBeInTheDocument()
    )
  })

  it("does not open enrollment when only email is enabled by the server", async () => {
    let setups = 0
    await renderPanel({
      "GET /api/v1/me/security": () =>
        security({
          enabled: false,
          factors: [],
          allowed_methods: ["email"],
          backup_codes_remaining: 0,
        }),
      "POST /api/v1/me/2fa/setup": () => {
        setups++
        return json(200, {})
      },
    })
    await screen.findByText("Off")
    expect(
      screen.queryByRole("button", { name: "Turn on" })
    ).not.toBeInTheDocument()
    expect(screen.queryByRole("radio")).not.toBeInTheDocument()
    expect(setups).toBe(0)
  })
})

it("shows required UV-passkey MFA as on without forcing an OTP or unusable backup-code controls", async () => {
  await renderPanel({
    "GET /api/v1/me/security": () =>
      security({
        enabled: false,
        required: true,
        passkeys_enrolled: true,
        factors: [],
        allowed_methods: ["totp"],
        backup_codes_remaining: 0,
      }),
  })
  await screen.findByText("On")
  expect(screen.queryByText("Off")).toBeNull()
  expect(
    screen.getByRole("button", { name: "Add a method" })
  ).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: /regenerate/i })).toBeNull()
  expect(screen.queryByRole("button", { name: "Turn off" })).toBeNull()
})
