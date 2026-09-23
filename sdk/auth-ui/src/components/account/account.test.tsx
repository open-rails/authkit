// @vitest-environment jsdom
import "../../test/dom.ts"

import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import { authError, json, stubFetch } from "../../client/testing.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { noContent, session, token } from "../../react/testing.tsx"
import {
  AccountSecurity,
  ContactPanel,
  DeleteAccountPanel,
  LinkedProvidersPanel,
  PasswordPanel,
  SessionsPanel,
  StepUpProvider,
  TwoFactorPanel,
} from "./index.ts"
import { SolanaLinkRow } from "../../solana/SolanaLinkRow.tsx"

// input-otp probes password-manager overlays with it; jsdom lacks it.
document.elementFromPoint ??= () => null

const profile = (extra: Record<string, unknown> = {}) =>
  json(200, {
    id: "u1",
    username: "u1",
    email: "a@x.test",
    phone_number: null,
    email_verified: true,
    phone_verified: false,
    has_password: true,
    roles: [],
    entitlements: [],
    linked_providers: [],
    naming: {},
    security: { step_up_required_for_sensitive_actions: false },
    ...extra,
  })

const capabilities = (password: Record<string, unknown> = {}) =>
  json(200, {
    registration: { mode: "open", invite_token_required: false },
    external_login_providers: [
      {
        id: "github",
        name: "GitHub",
        supports_login: true,
        supports_registration: true,
        supports_link: true,
      },
    ],
    password: { login: true, ...password },
    passwordless: { enabled: false },
    passkeys: { login: false },
    solana: { login: false },
    verification: { registration: "required" },
  })

type Routes = Parameters<typeof stubFetch>[0]

async function renderSignedIn(ui: ReactNode, routes: Routes) {
  const fetch = stubFetch({
    "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
    "GET /api/v1/me": () => profile(),
    "GET /api/v1/capabilities": () => capabilities(),
    ...routes,
  })
  const client = createAuthClient({ fetch })
  const view = render(
    <AuthProvider client={client} autoStart={false}>
      <AuthUiProvider>{ui}</AuthUiProvider>
    </AuthProvider>
  )
  await act(() =>
    client.signInWithPassword({ identifier: "a@x.test", password: "pw" })
  )
  return { ...view, client, fetch, user: userEvent.setup() }
}

const stepUpRequired = (metadata: Record<string, unknown>) =>
  authError(403, "step_up_required", { max_age_seconds: 900, ...metadata })

const fresh = () =>
  json(200, {
    token_set: { access_token: token({ sub: "u1", sid: "s1", auth_time: 2 }) },
    fresh_auth: { step_up_required_for_sensitive_actions: false },
  })

describe("PasswordPanel", () => {
  it("validates against the advertised policy, steps up and retries", async () => {
    const bodies: unknown[] = []
    const { user } = await renderSignedIn(
      <StepUpProvider>
        <PasswordPanel />
      </StepUpProvider>,
      {
        "GET /api/v1/capabilities": () => capabilities({ min_length: 12 }),
        "POST /api/v1/user/password": [
          stepUpRequired({ step_up_methods: ["password"] }),
          noContent(),
        ],
        "POST /api/v1/step-up/password": (init) => {
          bodies.push(JSON.parse(String(init.body)))
          return bodies.length === 1
            ? authError(401, "invalid_password")
            : fresh()
        },
      }
    )
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    const dialog = screen.getByRole("dialog", { name: "Change password" })
    expect(dialog).toHaveTextContent("Use at least 12 characters.")
    await user.type(within(dialog).getByLabelText("New password"), "short-pw-1")
    await user.click(
      within(dialog).getByRole("button", { name: "Update password" })
    )
    expect(dialog).toHaveTextContent("Password must be at least 12 characters")

    await user.clear(within(dialog).getByLabelText("New password"))
    await user.type(
      within(dialog).getByLabelText("New password"),
      "long-enough-1"
    )
    await user.type(
      within(dialog).getByLabelText("Confirm password"),
      "long-enough-1"
    )
    await user.click(
      within(dialog).getByRole("button", { name: "Update password" })
    )

    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    await user.type(within(stepUp).getByLabelText("Password"), "wrong")
    await user.click(within(stepUp).getByRole("button", { name: "Confirm" }))
    expect(await within(stepUp).findByRole("alert")).toHaveTextContent(
      "Incorrect password"
    )
    await user.clear(within(stepUp).getByLabelText("Password"))
    await user.type(within(stepUp).getByLabelText("Password"), "pw")
    await user.click(within(stepUp).getByRole("button", { name: "Confirm" }))

    expect(
      await screen.findByText("Password updated successfully!")
    ).toBeInTheDocument()
    expect(bodies).toEqual([{ password: "wrong" }, { password: "pw" }])
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    )
  })
})

describe("StepUpDialog", () => {
  it("sends an email code; a wrong code is retryable, an expired one prompts a resend", async () => {
    const sent: unknown[] = []
    const { user } = await renderSignedIn(<TwoFactorPanel />, {
      "GET /api/v1/user/2fa": () =>
        json(200, {
          enabled: true,
          method: "email",
          factors: [{ id: "f1", method: "email", is_default: true }],
          allowed_methods: ["email", "totp"],
          backup_codes_remaining: 8,
        }),
      "POST /api/v1/user/2fa/backup-codes": [
        stepUpRequired({
          step_up_methods: ["2fa"],
          mfa_required: true,
          step_up_2fa: {
            methods: ["email"],
            default_method: "email",
            options: [{ method: "email", is_default: true }],
          },
        }),
        json(200, { backup_codes: ["aaaa-1111", "bbbb-2222"] }),
      ],
      "POST /api/v1/step-up/2fa": (init) => {
        const body = JSON.parse(String(init.body))
        sent.push(body)
        if (!body.code)
          return authError(403, "2fa_required", {
            method: "email",
            verification_id: "a***@x.test",
          })
        if (body.code === "111111") return authError(401, "invalid_code")
        if (body.code === "333333") return authError(401, "2fa_code_expired")
        return fresh()
      },
    })
    expect(await screen.findByText("8 unused codes left")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Generate new codes" }))
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Generate new codes",
      })
    )
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    await user.click(within(stepUp).getByRole("button", { name: "Send code" }))
    expect(
      await within(stepUp).findByText("Enter the code we sent to a***@x.test.")
    ).toBeInTheDocument()

    await user.type(within(stepUp).getByRole("textbox"), "111111")
    expect(
      await within(stepUp).findByText("Invalid verification code.")
    ).toBeInTheDocument()
    expect(
      within(stepUp).queryByRole("button", { name: "Send a new code" })
    ).toBeNull()
    await user.type(within(stepUp).getByRole("textbox"), "333333")
    expect(
      await within(stepUp).findByText(
        "That code can't be used again. Send a new code to continue."
      )
    ).toBeInTheDocument()
    expect(within(stepUp).queryByRole("textbox")).toBeNull()
    await user.click(
      within(stepUp).getByRole("button", { name: "Send a new code" })
    )
    await user.type(await within(stepUp).findByRole("textbox"), "222222")

    const codes = await screen.findByRole("list", { name: "Backup codes" })
    expect(
      within(codes)
        .getAllByRole("listitem")
        .map((li) => li.textContent)
    ).toEqual(["aaaa-1111", "bbbb-2222"])
    expect(sent).toEqual([
      { method: "email" },
      { code: "111111", method: "email" },
      { code: "333333", method: "email" },
      { method: "email" },
      { code: "222222", method: "email" },
    ])
  })
})

describe("TwoFactorPanel", () => {
  it("enrolls TOTP with a QR code and shows the backup codes once", async () => {
    let enabled = false
    const { user } = await renderSignedIn(<TwoFactorPanel />, {
      "GET /api/v1/user/2fa": () =>
        json(200, {
          enabled,
          method: enabled ? "totp" : "",
          factors: enabled
            ? [{ id: "f1", method: "totp", is_default: true }]
            : [],
          allowed_methods: ["email", "sms", "totp"],
        }),
      "POST /api/v1/user/2fa": (init) => {
        const body = JSON.parse(String(init.body))
        if (!body.code)
          return json(200, {
            secret: "JBSWY3DPEHPK3PXP",
            otpauth_uri: "otpauth://totp/x:a?secret=JBSWY3DPEHPK3PXP",
          })
        enabled = true
        return json(200, {
          enabled: true,
          method: "totp",
          backup_codes: ["c1-c1"],
        })
      },
    })
    await user.click(await screen.findByRole("button", { name: "Turn on" }))
    expect(
      screen.getByRole("radio", { name: /Authenticator app/ })
    ).toBeChecked()
    await user.click(screen.getByRole("button", { name: "Continue" }))
    expect(await screen.findByText(/Scan this with/)).toBeInTheDocument()
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument()
    expect(
      screen.getByText("Open in authenticator app").closest("a")
    ).toHaveAttribute("href", "otpauth://totp/x:a?secret=JBSWY3DPEHPK3PXP")
    await user.type(
      screen.getByRole("textbox", { name: "Verification code" }),
      "123456"
    )
    expect(await screen.findByText("c1-c1")).toBeInTheDocument()
    await user.click(
      screen.getByRole("button", { name: "I've saved my backup codes" })
    )
    expect(screen.queryByText("c1-c1")).not.toBeInTheDocument()
    expect(await screen.findByText("On")).toBeInTheDocument()
  })
})

describe("ContactPanel", () => {
  it("changes email with a code; a wrong code stays retryable", async () => {
    const requested: unknown[] = []
    let confirms = 0
    const { user } = await renderSignedIn(
      <ContactPanel channels={["email"]} />,
      {
        "POST /api/v1/verify/request": (init) => {
          requested.push(JSON.parse(String(init.body)))
          return noContent()
        },
        "POST /api/v1/verify/confirm": () =>
          ++confirms <= 2
            ? authError(400, "invalid_or_expired_code")
            : noContent(),
      }
    )
    await user.click(await screen.findByRole("button", { name: "Change" }))
    await user.type(screen.getByLabelText("New email address"), "a@x.test")
    await user.click(screen.getByRole("button", { name: "Send code" }))
    expect(
      screen.getByText("The new email is the same as your current email")
    ).toBeInTheDocument()
    await user.clear(screen.getByLabelText("New email address"))
    await user.type(screen.getByLabelText("New email address"), "b@x.test")
    await user.click(screen.getByRole("button", { name: "Send code" }))

    for (let i = 1; i <= 2; i++) {
      const box = await screen.findByRole("textbox", {
        name: "Verification code",
      })
      await waitFor(() => expect(box).toBeEnabled())
      await user.type(box, "999999")
      await waitFor(() => expect(confirms).toBe(i))
      expect(
        await screen.findByText(
          "The verification code is invalid or has expired."
        )
      ).toBeInTheDocument()
      expect(
        screen.queryByRole("button", { name: "Send a new code" })
      ).toBeNull()
    }
    const box = screen.getByRole("textbox", { name: "Verification code" })
    await waitFor(() => expect(box).toBeEnabled())
    await user.type(box, "123456")
    expect(
      await screen.findByText("Email changed successfully!")
    ).toBeInTheDocument()
    expect(requested).toEqual([{ identifier: "b@x.test" }])
  })
})

describe("SessionsPanel", () => {
  it("marks this device and signs out the selected sessions in one batch", async () => {
    const revoked: string[] = []
    const row = (id: string, ua: string) => ({
      session_id: id,
      family_id: "f",
      created_at: new Date().toISOString(),
      last_used_at: new Date().toISOString(),
      expires_at: "",
      ip: "10.0.0.1",
      ua,
    })
    const mac =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    const iphone =
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    const { user } = await renderSignedIn(<SessionsPanel />, {
      "GET /api/v1/user/sessions": () =>
        json(200, {
          object: "list",
          data: [row("s2", mac), row("s1", mac), row("s3", iphone)],
        }),
      "DELETE /api/v1/user/sessions/s2": (init) => {
        revoked.push(init.url.split("/").pop()!)
        return noContent()
      },
      "DELETE /api/v1/user/sessions/s3": (init) => {
        revoked.push(init.url.split("/").pop()!)
        return noContent()
      },
    })
    const list = await screen.findByRole("list", { name: "Active sessions" })
    const items = within(list).getAllByRole("listitem")
    expect(items[0]).toHaveTextContent("This device")
    expect(within(items[0]).queryByRole("checkbox")).not.toBeInTheDocument()
    expect(list).toHaveTextContent("Safari on iOS")

    await user.click(
      screen.getByRole("checkbox", { name: "Select Safari on macOS" })
    )
    await user.click(
      screen.getByRole("checkbox", { name: "Select Safari on iOS" })
    )
    await user.click(
      screen.getByRole("button", { name: "Sign out selected (2)" })
    )
    await waitFor(() =>
      expect(within(list).getAllByRole("listitem")).toHaveLength(1)
    )
    expect(revoked.sort()).toEqual(["s2", "s3"])
    expect(
      screen.getByText("You're not signed in anywhere else.")
    ).toBeInTheDocument()
  })
})

describe("LinkedProvidersPanel", () => {
  it("confirms unlinking and explains the last sign-in method", async () => {
    const { user } = await renderSignedIn(<LinkedProvidersPanel />, {
      "GET /api/v1/me": () =>
        profile({ has_password: false, linked_providers: ["github"] }),
      "DELETE /api/v1/user/providers/github": () =>
        authError(400, "cannot_unlink_last_login_method"),
    })
    await user.click(await screen.findByRole("button", { name: "Unlink" }))
    const confirm = screen.getByRole("alertdialog", { name: "Unlink GitHub?" })
    await user.click(within(confirm).getByRole("button", { name: "Unlink" }))
    expect(
      await screen.findByText("You can't unlink your last way to sign in.")
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        "Add a password or link another sign-in option before unlinking this one."
      )
    ).toBeInTheDocument()
  })
})

describe("DeleteAccountPanel", () => {
  it("needs the typed confirmation, then reports deletion", async () => {
    const onDeleted = vi.fn()
    const { user, client } = await renderSignedIn(
      <DeleteAccountPanel onDeleted={onDeleted} />,
      { "DELETE /api/v1/user": () => noContent() }
    )
    await user.click(
      await screen.findByRole("button", { name: "Delete account" })
    )
    const dialog = screen.getByRole("alertdialog")
    const submit = within(dialog).getByRole("button", {
      name: "Delete account",
    })
    expect(submit).toBeDisabled()
    await user.type(within(dialog).getByLabelText("Confirmation"), "DELETE")
    await user.click(submit)
    await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce())
    expect(client.getSnapshot().status).toBe("anonymous")
  })
})

describe("AccountSecurity", () => {
  it("renders every panel under one step-up dialog", async () => {
    await renderSignedIn(
      <AccountSecurity
        sections={["contact", "password", "providers", "delete"]}
      />,
      {}
    )
    for (const name of [
      "Contact details",
      "Password",
      "Linked login options",
      "Danger zone",
    ])
      expect(await screen.findByText(name)).toBeInTheDocument()
    expect(screen.queryByText("Active sessions")).not.toBeInTheDocument()
  })
})

describe("SolanaLinkRow", () => {
  it("links through a lazily acquired signer", async () => {
    const signMessage = vi.fn(async () => new Uint8Array(64).fill(1))
    const acquireSigner = vi.fn(async () => ({ publicKey: "W", signMessage }))
    const linked: unknown[] = []
    const { user } = await renderSignedIn(
      <StepUpProvider>
        <SolanaLinkRow acquireSigner={acquireSigner} />
      </StepUpProvider>,
      {
        "POST /api/v1/solana/challenge": () => json(200, { message: "m" }),
        "POST /api/v1/solana/link": (init) => {
          linked.push(JSON.parse(String(init.body)))
          return json(200, { solana_address: "W" })
        },
      }
    )
    await user.click(await screen.findByRole("button", { name: /link/i }))
    await waitFor(() => expect(linked).toHaveLength(1))
    expect(acquireSigner).toHaveBeenCalledOnce()
    expect(signMessage).toHaveBeenCalledOnce()
    expect(linked[0]).toMatchObject({ output: { account: { address: "W" } } })
  })
})
