// @vitest-environment jsdom
import "../../test/dom.ts"

import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import type { SignInKey } from "../../client/types.ts"
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
import { noContent, session, signedIn } from "../../react/testing.tsx"
import {
  AccountSecurity,
  AccountProfile,
  ContactPanel,
  DeleteAccountPanel,
  LinkedProvidersPanel,
  PasswordPanel,
  SessionsPanel,
  SignInKeysPanel,
  StepUpProvider,
  TwoFactorPanel,
} from "./index.ts"
import { SolanaLinkRow } from "../../solana/SolanaLinkRow.tsx"
import { SignInDialog } from "../sign-in/SignInDialog.tsx"

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
    root_role: null,
    entitlements: [],
    providers: [],
    solana_wallet: null,
    naming: {},
    ...extra,
  })

const capabilities = (
  password: Record<string, unknown> = {},
  passkeys = false
) =>
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
    password: { ...password },
    passwordless: { enabled: false },
    passkeys: { login: passkeys },
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
  authError(401, "step_up_required", {
    max_age_seconds: 900,
    factors: [],
    ...metadata,
  })

const fresh = () =>
  json(
    200,
    signedIn(
      { sub: "u1", sid: "s1", auth_time: 2 },
      {
        fresh_auth: {
          last_authenticated_at: null,
          step_up_required_for_sensitive_actions: false,
          step_up_required_in_seconds: 900,
          auth_methods: ["pwd"],
        },
      }
    )
  )

const factor = (id: string, method: string, isDefault: boolean) => ({
  id,
  method,
  is_default: isDefault,
  destination: method === "totp" ? null : "a***@x.test",
})

// GET /me/security with these second factors.
const security = (twoFactor: {
  enabled: boolean
  factors: ReturnType<typeof factor>[]
  allowed_methods: string[]
  backup_codes_remaining: number
}) =>
  json(200, {
    last_authenticated_at: null,
    step_up_required_for_sensitive_actions: false,
    step_up_required_in_seconds: 900,
    auth_methods: ["pwd"],
    step_up_methods: twoFactor.enabled ? ["2fa"] : ["password"],
    two_factor: twoFactor,
  })

describe("PasswordPanel", () => {
  const securityWithoutFactors = () =>
    security({
      enabled: false,
      factors: [],
      allowed_methods: ["totp"],
      backup_codes_remaining: 0,
    })
  const setup = (routes: Routes = {}) =>
    renderSignedIn(<PasswordPanel />, {
      "GET /api/v1/me/security": securityWithoutFactors,
      "POST /api/v1/me/step-up/password": fresh,
      ...routes,
    })
  const confirmPassword = async (user: ReturnType<typeof userEvent.setup>) => {
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    await user.type(within(dialog).getByLabelText("Password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: "Confirm" }))
    return screen.findByRole("form", { name: "Change password" })
  }

  it("authenticates before showing any new-password field and retains failed authentication", async () => {
    const saves: unknown[] = []
    const { user } = await setup({
      "POST /api/v1/me/step-up/password": [
        authError(401, "invalid_password"),
        fresh(),
      ],
      "PUT /api/v1/me/password": (init) => {
        saves.push(JSON.parse(String(init.body)))
        return noContent()
      },
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    expect(screen.queryByLabelText("New password")).toBeNull()
    expect(screen.queryByLabelText("Confirm password")).toBeNull()
    expect(saves).toEqual([])
    const current = within(stepUp).getByLabelText("Password")
    expect(current).toHaveAttribute("name", "current-password")
    expect(current).toHaveAttribute("autocomplete", "current-password")
    await user.type(current, "wrong")
    await user.click(within(stepUp).getByRole("button", { name: "Confirm" }))
    expect(await within(stepUp).findByRole("alert")).toHaveTextContent(
      "Incorrect password"
    )
    expect(screen.queryByLabelText("New password")).toBeNull()
    await user.clear(current)
    const form = await confirmPassword(user)
    expect(
      form.querySelectorAll('input[autocomplete="new-password"]')
    ).toHaveLength(1)
    expect(within(form).queryByLabelText("Confirm password")).toBeNull()
    await user.type(
      within(form).getByLabelText("New password"),
      "new-test-password-1"
    )
    await user.click(
      within(form).getByRole("button", { name: "Update password" })
    )
    await waitFor(() =>
      expect(screen.queryByRole("form", { name: "Change password" })).toBeNull()
    )
    expect(saves).toEqual([{ new_password: "new-test-password-1" }])
  })

  it("retains Chrome password metadata and a failed save, then removes the successful form", async () => {
    const { user } = await setup({
      "PUT /api/v1/me/password": [authError(503, "server_busy"), noContent()],
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    const form = await confirmPassword(user)
    expect(form).toHaveAttribute("method", "post")
    expect(form).toHaveAttribute("autocomplete", "on")
    const account = form.querySelector('input[autocomplete="username"]')
    expect(account).toHaveValue("a@x.test")
    expect(account).toHaveAttribute("name", "username")
    expect(account).toHaveClass("hidden")
    const password = within(form).getByLabelText("New password")
    expect(password).toHaveAttribute("name", "new-password")
    expect(password).toHaveAttribute("autocomplete", "new-password")
    await user.type(password, "new-test-password-1")
    await user.click(
      within(form).getByRole("button", { name: "Update password" })
    )
    await screen.findByText(/Server is busy|server_busy|busy/i)
    expect(password).toHaveValue("new-test-password-1")
    await user.click(
      within(form).getByRole("button", { name: "Update password" })
    )
    await waitFor(() =>
      expect(screen.queryByRole("form", { name: "Change password" })).toBeNull()
    )
    expect(screen.queryByDisplayValue("new-test-password-1")).toBeNull()
  })

  it("authenticates a passwordless account by email before showing the single set-password input", async () => {
    const { user } = await setup({
      "GET /api/v1/me": () => profile({ has_password: false }),
      "GET /api/v1/me/security": () =>
        json(200, {
          step_up_methods: ["email"],
          two_factor: { enabled: false, factors: [] },
        }),
      "POST /api/v1/me/step-up/code/send": noContent,
      "POST /api/v1/me/step-up/code": fresh,
      "PUT /api/v1/me/password": noContent,
    })
    await user.click(
      await screen.findByRole("button", { name: "Set password" })
    )
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    expect(screen.queryByLabelText("New password")).toBeNull()
    await user.click(within(dialog).getByRole("button", { name: "Send code" }))
    await user.type(
      await within(dialog).findByRole("textbox", { name: "Verification code" }),
      "123456"
    )
    const form = await screen.findByRole("form", { name: "Set password" })
    expect(
      form.querySelectorAll('input[autocomplete="new-password"]')
    ).toHaveLength(1)
    await user.type(
      within(form).getByLabelText("New password"),
      "new-test-password-1"
    )
    await user.click(
      within(form).getByRole("button", { name: "Update password" })
    )
    await waitFor(() =>
      expect(screen.queryByRole("form", { name: "Set password" })).toBeNull()
    )
  })

  it("uses the existing authenticator factor before opening the editor", async () => {
    const verified: unknown[] = []
    const { user } = await setup({
      "GET /api/v1/me/security": () =>
        security({
          enabled: true,
          factors: [factor("totp", "totp", true)],
          allowed_methods: ["totp"],
          backup_codes_remaining: 5,
        }),
      "POST /api/v1/me/step-up/2fa": (init) => {
        verified.push(JSON.parse(String(init.body)))
        return fresh()
      },
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    expect(screen.queryByLabelText("New password")).toBeNull()
    await user.type(
      within(dialog).getByRole("textbox", { name: "Verification code" }),
      "123456"
    )
    const form = await screen.findByRole("form", { name: "Change password" })
    expect(
      form.querySelectorAll('input[autocomplete="new-password"]')
    ).toHaveLength(1)
    expect(verified).toEqual([{ code: "123456", factor_id: "totp" }])
  })

  it("does not present an account UUID as an autofill username", async () => {
    const { user } = await setup({
      "GET /api/v1/me": () =>
        profile({ email: null, username: "", phone_number: null }),
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    const form = await confirmPassword(user)
    expect(form.querySelector('input[autocomplete="username"]')).toBeNull()
  })

  it("keeps the editor closed when preflight fails or authentication is cancelled", async () => {
    const { user } = await setup({
      "GET /api/v1/me/security": [
        authError(503, "server_busy"),
        securityWithoutFactors(),
      ],
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    await screen.findByText(/Server is busy|server_busy|busy/i)
    expect(screen.queryByLabelText("New password")).toBeNull()
    await user.click(screen.getByRole("button", { name: "Change password" }))
    await screen.findByRole("dialog", { name: "Confirm it's you" })
    await user.keyboard("{Escape}")
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Change password" })
      ).not.toBeDisabled()
    )
    expect(screen.queryByLabelText("New password")).toBeNull()
  })

  it("does not reopen a sensitive editor after signing in again as the same account", async () => {
    let login = 0
    const { user, client } = await setup({
      "POST /api/v1/password/login": () =>
        session({ sub: "u1", sid: ++login === 1 ? "s1" : "s2" }),
      "DELETE /api/v1/logout": noContent,
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    await confirmPassword(user)
    await act(async () => {
      await client.signOut()
    })
    await act(async () => {
      await client.signInWithPassword({
        identifier: "a@x.test",
        password: "pw",
      })
    })
    expect(screen.queryByLabelText("New password")).toBeNull()
  })

  it.each([true, false])(
    "shows a single compact password row (set=%s)",
    async (hasPassword) => {
      await setup({
        "GET /api/v1/me": () => profile({ has_password: hasPassword }),
      })
      expect(
        await screen.findByText(hasPassword ? "----" : "none")
      ).toBeInTheDocument()
      expect(
        screen.getByRole("button", {
          name: hasPassword ? "Change password" : "Set password",
        })
      ).toBeInTheDocument()
      expect(screen.queryByText("Set")).toBeNull()
      expect(screen.queryByRole("heading", { name: "Password" })).toBeNull()
    }
  )

  it("validates the new password policy after authentication and can re-authenticate if freshness expires", async () => {
    let saves = 0
    const { user } = await setup({
      "GET /api/v1/capabilities": () => capabilities({ min_length: 12 }),
      "PUT /api/v1/me/password": () =>
        ++saves === 1
          ? stepUpRequired({ step_up_methods: ["password"] })
          : noContent(),
    })
    await user.click(
      await screen.findByRole("button", { name: "Change password" })
    )
    const form = await confirmPassword(user)
    await user.type(within(form).getByLabelText("New password"), "short-pw-1")
    await user.click(
      within(form).getByRole("button", { name: "Update password" })
    )
    expect(form).toHaveTextContent("Password must be at least 12 characters")
    expect(saves).toBe(0)
    await user.clear(within(form).getByLabelText("New password"))
    await user.type(
      within(form).getByLabelText("New password"),
      "long-enough-1"
    )
    await user.click(
      within(form).getByRole("button", { name: "Update password" })
    )
    const again = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    await user.type(within(again).getByLabelText("Password"), "pw")
    await user.click(within(again).getByRole("button", { name: "Confirm" }))
    await waitFor(() =>
      expect(screen.queryByRole("form", { name: "Change password" })).toBeNull()
    )
    expect(saves).toBe(2)
  })
})

describe("StepUpDialog", () => {
  it("sends an email code; a wrong code is retryable, an expired one prompts a resend", async () => {
    const sent: unknown[] = []
    const { user } = await renderSignedIn(<TwoFactorPanel />, {
      "GET /api/v1/me/security": () =>
        security({
          enabled: true,
          factors: [factor("f1", "email", true)],
          allowed_methods: ["email", "totp"],
          backup_codes_remaining: 8,
        }),
      "POST /api/v1/me/2fa/backup-codes": [
        stepUpRequired({
          step_up_methods: ["2fa"],
          factors: [factor("f1", "email", true)],
        }),
        json(200, { backup_codes: ["aaaa-1111", "bbbb-2222"] }),
      ],
      "POST /api/v1/me/step-up/2fa/send": (init) => {
        sent.push({ send: JSON.parse(String(init.body)) })
        return new Response(null, { status: 202 })
      },
      "POST /api/v1/me/step-up/2fa": (init) => {
        const body = JSON.parse(String(init.body))
        sent.push(body)
        if (body.code === "111111") return authError(401, "invalid_code")
        if (body.code === "333333") return authError(401, "code_expired")
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
      { send: { factor_id: "f1" } },
      { code: "111111", factor_id: "f1" },
      { code: "333333", factor_id: "f1" },
      { send: { factor_id: "f1" } },
      { code: "222222", factor_id: "f1" },
    ])
  })
})

describe("StepUpDialog sign-in methods", () => {
  const deleteAccount = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.click(
      await screen.findByRole("button", { name: "Delete account" })
    )
    const confirm = screen.getByRole("alertdialog")
    await user.type(within(confirm).getByLabelText("Confirmation"), "DELETE")
    await user.click(
      within(confirm).getByRole("button", { name: "Delete account" })
    )
    return screen.findByRole("dialog", { name: "Confirm it's you" })
  }

  it("steps up a passwordless account with a code to its email", async () => {
    const calls: unknown[] = []
    const onDeleted = vi.fn()
    const { user } = await renderSignedIn(
      <DeleteAccountPanel onDeleted={onDeleted} />,
      {
        "GET /api/v1/me": () => profile({ has_password: false }),
        "DELETE /api/v1/me": [
          stepUpRequired({ step_up_methods: ["email"] }),
          noContent(),
        ],
        "POST /api/v1/me/step-up/code/send": (init) => {
          calls.push({ send: JSON.parse(String(init.body)) })
          return new Response(null, { status: 202 })
        },
        "POST /api/v1/me/step-up/code": (init) => {
          const body = JSON.parse(String(init.body))
          calls.push(body)
          return body.code === "111111"
            ? authError(401, "invalid_code")
            : fresh()
        },
      }
    )
    const stepUp = await deleteAccount(user)
    expect(
      await within(stepUp).findByText("We'll send a one-time code to a@x.test.")
    ).toBeInTheDocument()
    expect(within(stepUp).queryByLabelText("Password")).toBeNull()
    await user.click(within(stepUp).getByRole("button", { name: "Send code" }))
    expect(
      await within(stepUp).findByText("Enter the code we sent to a@x.test.")
    ).toBeInTheDocument()
    await user.type(within(stepUp).getByRole("textbox"), "111111")
    expect(
      await within(stepUp).findByText("Invalid verification code.")
    ).toBeInTheDocument()
    await user.type(within(stepUp).getByRole("textbox"), "222222")
    await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce())
    expect(calls).toEqual([
      { send: { channel: "email" } },
      { code: "111111" },
      { code: "222222" },
    ])
  })

  it("steps up with a passkey, second factor or not; a closed prompt changes nothing", async () => {
    const get = stubPasskey()
    get.mockRejectedValueOnce(new DOMException("closed", "NotAllowedError"))
    const finished: unknown[] = []
    const { user } = await renderSignedIn(<TwoFactorPanel />, {
      "GET /api/v1/me/security": () =>
        security({
          enabled: true,
          factors: [factor("f1", "totp", true)],
          allowed_methods: ["totp"],
          backup_codes_remaining: 8,
        }),
      "POST /api/v1/me/2fa/backup-codes": [
        stepUpRequired({
          step_up_methods: ["2fa", "passkey"],
          factors: [factor("f1", "totp", true)],
        }),
        json(200, { backup_codes: ["aaaa-1111"] }),
      ],
      "POST /api/v1/me/step-up/passkey/begin": passkeyOptions,
      "POST /api/v1/me/step-up/passkey": (init) => {
        finished.push(JSON.parse(String(init.body)))
        return fresh()
      },
    })
    await user.click(
      await screen.findByRole("button", { name: "Generate new codes" })
    )
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Generate new codes",
      })
    )
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    const usePasskey = within(stepUp).getByRole("button", {
      name: "Use a passkey",
    })
    await user.click(usePasskey)
    await waitFor(() => expect(get).toHaveBeenCalledOnce())
    expect(within(stepUp).queryByRole("alert")).toBeNull()
    expect(finished).toEqual([])

    await user.click(usePasskey)
    expect(
      await screen.findByRole("list", { name: "Backup codes" })
    ).toHaveTextContent("aaaa-1111")
    const options = get.mock.calls[1][0].publicKey
    expect(new Uint8Array(options?.challenge as ArrayBuffer)).toEqual(
      new Uint8Array([1, 2, 3])
    )
    expect(options?.allowCredentials).toHaveLength(1)
    expect(finished).toEqual([passkeyAssertion])
  })

  it("steps up with the linked wallet through a lazily acquired signer", async () => {
    const signMessage = vi.fn(async () => new Uint8Array(64).fill(1))
    const acquireSolanaSigner = vi.fn(async () => ({
      publicKey: "W",
      signMessage,
    }))
    const signed: unknown[] = []
    const onDeleted = vi.fn()
    const { user } = await renderSignedIn(
      <StepUpProvider acquireSolanaSigner={acquireSolanaSigner}>
        <DeleteAccountPanel onDeleted={onDeleted} />
      </StepUpProvider>,
      {
        "GET /api/v1/me": () => profile({ email: null, has_password: false }),
        "DELETE /api/v1/me": [
          stepUpRequired({ step_up_methods: ["solana"] }),
          noContent(),
        ],
        "POST /api/v1/me/step-up/solana/challenge": () =>
          json(200, {
            nonce: "n",
            issued_at: "2026-09-30T00:00:00Z",
            message: "m",
          }),
        "POST /api/v1/me/step-up/solana": (init) => {
          signed.push(JSON.parse(String(init.body)))
          return fresh()
        },
      }
    )
    const stepUp = await deleteAccount(user)
    await user.click(
      within(stepUp).getByRole("button", { name: "Use your wallet" })
    )
    await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce())
    expect(acquireSolanaSigner).toHaveBeenCalledOnce()
    expect(signMessage).toHaveBeenCalledWith(new TextEncoder().encode("m"))
    expect(signed).toHaveLength(1)
    expect(signed[0]).toMatchObject({
      output: {
        account: { address: "W" },
        signature: btoa(String.fromCharCode(...new Uint8Array(64).fill(1))),
        signedMessage: btoa("m"),
      },
    })
  })

  it("offers no wallet without a signer", async () => {
    const { user } = await renderSignedIn(<DeleteAccountPanel />, {
      "DELETE /api/v1/me": [stepUpRequired({ step_up_methods: ["solana"] })],
    })
    const stepUp = await deleteAccount(user)
    expect(stepUp).toHaveTextContent(
      "No reauthentication methods are available for this account."
    )
  })
})

describe("StepUpProvider return", () => {
  it("adopts the session an OIDC step-up's #code= returns with", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
        "GET /api/v1/capabilities": () => capabilities(),
        "POST /api/v1/oidc/exchange": (init) => {
          expect(JSON.parse(String(init.body))).toEqual({ code: "one-time" })
          return fresh()
        },
      }),
    })
    await client.signInWithPassword({ identifier: "a@x.test", password: "pw" })
    window.history.replaceState(null, "", "/account#code=one-time")
    render(
      <AuthProvider client={client} autoStart={false}>
        <AuthUiProvider>
          <StepUpProvider>
            <p>page</p>
          </StepUpProvider>
        </AuthUiProvider>
      </AuthProvider>
    )
    await waitFor(() =>
      expect(client.getSnapshot()).toMatchObject({ claims: { auth_time: 2 } })
    )
    expect(window.location.hash).toBe("")
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  })

  it("reports a failed step-up", async () => {
    window.history.replaceState(null, "", "/account#error=provider_error")
    await renderSignedIn(
      <StepUpProvider>
        <p>page</p>
      </StepUpProvider>,
      {}
    )
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    expect(dialog).toHaveTextContent("Reauthentication failed.")
  })
})

describe("TwoFactorPanel", () => {
  it("enrolls TOTP with a QR code and shows the backup codes once", async () => {
    let enabled = false
    const { user } = await renderSignedIn(<TwoFactorPanel />, {
      "GET /api/v1/me/security": () =>
        security({
          enabled,
          factors: enabled ? [factor("f1", "totp", true)] : [],
          allowed_methods: ["email", "sms", "totp"],
          backup_codes_remaining: 0,
        }),
      "POST /api/v1/me/2fa/setup": () =>
        json(200, {
          method: "totp",
          destination: null,
          secret: "JBSWY3DPEHPK3PXP",
          otpauth_uri: "otpauth://totp/x:a?secret=JBSWY3DPEHPK3PXP",
        }),
      "POST /api/v1/me/2fa/factors": (init) => {
        expect(JSON.parse(String(init.body))).toEqual({
          method: "totp",
          code: "123456",
        })
        enabled = true
        return json(201, {
          factor: factor("f1", "totp", true),
          backup_codes: ["c1-c1"],
          auth: signedIn({ sub: "u1", sid: "s1", auth_time: 3 }),
        })
      },
    })
    await user.click(await screen.findByRole("button", { name: "Turn on" }))
    expect(
      screen.getByRole("radio", { name: /Authenticator app/ })
    ).toBeChecked()
    await user.click(screen.getByRole("button", { name: "Continue" }))
    expect(
      await screen.findByText(/Open your authenticator app/)
    ).toBeInTheDocument()
    expect(screen.queryByText("JBSWY3DPEHPK3PXP")).toBeNull()
    await user.click(
      screen.getByRole("button", { name: "Show manual setup key" })
    )
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument()
    expect(screen.queryByText("Set up on this device")).toBeNull()
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

  it("makes a factor the default and removes one", async () => {
    const calls: string[] = []
    let factors = [factor("f1", "totp", true), factor("f2", "email", false)]
    const { user } = await renderSignedIn(<TwoFactorPanel />, {
      "GET /api/v1/me/security": () =>
        security({
          enabled: true,
          factors,
          allowed_methods: ["email", "totp"],
          backup_codes_remaining: 5,
        }),
      "PATCH /api/v1/me/2fa/factors/f2": (init) => {
        calls.push(`PATCH f2 ${String(init.body)}`)
        factors = [factor("f1", "totp", false), factor("f2", "email", true)]
        return json(200, factors[1])
      },
      "DELETE /api/v1/me/2fa/factors/f1": () => {
        calls.push("DELETE f1")
        factors = [factor("f2", "email", true)]
        return noContent()
      },
    })
    await user.click(
      await screen.findByRole("button", { name: "Make default" })
    )
    await waitFor(() => expect(calls).toEqual(['PATCH f2 {"default":true}']))
    await user.click(
      await screen.findByRole("button", { name: "Remove Authenticator app" })
    )
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Remove",
      })
    )
    await waitFor(() => expect(calls).toContain("DELETE f1"))
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Remove Authenticator app" })
      ).not.toBeInTheDocument()
    )
  })
})

describe("ContactPanel", () => {
  it("shows contact rows without the section heading", async () => {
    await renderSignedIn(<ContactPanel />, {})
    expect(await screen.findByText("a@x.test")).toBeInTheDocument()
    expect(screen.queryByText("Contact details")).toBeNull()
  })
  it("changes email with a code; a wrong code stays retryable", async () => {
    const requested: unknown[] = []
    let confirms = 0
    const { user } = await renderSignedIn(
      <ContactPanel channels={["email"]} />,
      {
        "PUT /api/v1/me/email": (init) => {
          requested.push(JSON.parse(String(init.body)))
          return new Response(null, { status: 202 })
        },
        "POST /api/v1/verify/confirm": () =>
          ++confirms <= 2 ? authError(401, "invalid_code") : noContent(),
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
        await screen.findByText("Invalid verification code.")
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
    expect(requested).toEqual([{ email: "b@x.test" }])
  })

  it("verifies an unproven phone, and removes it after a step-up", async () => {
    let phone: string | null = "+15550100"
    const calls: string[] = []
    const { user } = await renderSignedIn(
      <StepUpProvider>
        <ContactPanel channels={["phone"]} />
      </StepUpProvider>,
      {
        "GET /api/v1/me": () =>
          profile({ phone_number: phone, phone_verified: false }),
        "POST /api/v1/verify/request": (init) => {
          calls.push(`request ${String(init.body)}`)
          return new Response(null, { status: 202 })
        },
        "POST /api/v1/verify/confirm": () => noContent(),
        "DELETE /api/v1/me/phone": () => {
          calls.push("delete")
          if (calls.filter((c) => c === "delete").length === 1)
            return stepUpRequired({ step_up_methods: ["password"] })
          phone = null
          return noContent()
        },
        "POST /api/v1/me/step-up/password": () => fresh(),
      }
    )
    await user.click(await screen.findByRole("button", { name: "Verify" }))
    await user.type(
      await screen.findByRole("textbox", { name: "Verification code" }),
      "123456"
    )
    expect(
      await screen.findByText("Phone number verified!")
    ).toBeInTheDocument()
    expect(calls).toEqual(['request {"identifier":"+15550100"}'])
    calls.length = 0
    await user.click(screen.getByRole("button", { name: "Close" }))

    await user.click(screen.getByRole("button", { name: "Remove" }))
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Remove",
      })
    )
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    await user.type(within(stepUp).getByLabelText("Password"), "pw")
    await user.click(within(stepUp).getByRole("button", { name: "Confirm" }))
    expect(await screen.findByText("None set")).toBeInTheDocument()
  })
})

describe("SessionsPanel", () => {
  it("marks this device and signs out the selected sessions in one batch", async () => {
    const revoked: string[] = []
    const row = (id: string, ua: string) => ({
      id,
      created_at: new Date().toISOString(),
      last_used_at: new Date().toISOString(),
      expires_at: null,
      ip: "10.0.0.1",
      user_agent: ua,
      current: id === "s1",
    })
    const mac =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    const iphone =
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    const { user } = await renderSignedIn(<SessionsPanel />, {
      "GET /api/v1/me/sessions": () =>
        json(200, {
          data: [row("s2", mac), row("s1", mac), row("s3", iphone)],
          next_cursor: null,
          total: null,
        }),
      "DELETE /api/v1/me/sessions/s2": (init) => {
        revoked.push(init.url.split("/").pop()!)
        return noContent()
      },
      "DELETE /api/v1/me/sessions/s3": (init) => {
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

  it("signs out everywhere else once while preserving the current session", async () => {
    const calls: string[] = []
    const row = (id: string) => ({
      id,
      created_at: new Date().toISOString(),
      last_used_at: new Date().toISOString(),
      expires_at: null,
      ip: null,
      user_agent: null,
      current: id === "s1",
    })
    const { user, client } = await renderSignedIn(<SessionsPanel />, {
      "GET /api/v1/me/sessions": () =>
        json(200, {
          data: [row("s1"), row("s2"), row("s3")],
          next_cursor: null,
          total: null,
        }),
      "DELETE /api/v1/me/sessions": () => {
        calls.push("others")
        return noContent()
      },
      "DELETE /api/v1/logout": () => {
        calls.push("logout")
        return noContent()
      },
    })
    const list = await screen.findByRole("list", { name: "Active sessions" })
    expect(
      screen.queryByRole("button", { name: "Sign out everywhere" })
    ).toBeNull()
    expect(
      screen.queryByRole("button", { name: "Sign out of all other sessions" })
    ).toBeNull()
    await user.click(
      screen.getByRole("button", { name: "Sign out everywhere else" })
    )
    await waitFor(() =>
      expect(within(list).getAllByRole("listitem")).toHaveLength(1)
    )
    expect(calls).toEqual(["others"])
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      claims: { sid: "s1" },
    })
    expect(within(list).getAllByRole("listitem")[0]).toHaveTextContent(
      "This device"
    )
    expect(screen.queryByRole("alertdialog")).toBeNull()
    expect(
      screen.queryByRole("button", { name: "Sign out everywhere else" })
    ).toBeNull()
  })
})

describe("SignInKeysPanel", () => {
  it("lists passkeys and device keys, renames and removes after a step-up", async () => {
    const calls: string[] = []
    let keys: SignInKey[] = [
      {
        id: "k1",
        kind: "passkey",
        label: "MacBook",
        created_at: new Date().toISOString(),
        last_used_at: null,
        current: false,
      },
      {
        id: "k2",
        kind: "device_key",
        label: null,
        created_at: new Date().toISOString(),
        last_used_at: new Date().toISOString(),
        current: false,
      },
    ]
    const { user } = await renderSignedIn(<SignInKeysPanel />, {
      "GET /api/v1/me/sign-in-keys": () =>
        json(200, { data: keys, next_cursor: null, total: null }),
      "PATCH /api/v1/me/sign-in-keys/k1": [
        stepUpRequired({ step_up_methods: ["password"] }),
        json(200, { ...keys[0], label: "Work laptop" }),
      ],
      "POST /api/v1/me/step-up/password": () => fresh(),
      "DELETE /api/v1/me/sign-in-keys/k2": () => {
        calls.push("delete k2")
        keys = keys.filter((k) => k.id !== "k2")
        return noContent()
      },
    })
    expect(await screen.findByText("MacBook")).toBeInTheDocument()
    expect(screen.getByText("Device key")).toBeInTheDocument()
    // Passkeys are off in /capabilities: nothing to add.
    expect(
      screen.queryByRole("button", { name: "Add a passkey" })
    ).not.toBeInTheDocument()

    await user.click(screen.getAllByRole("button", { name: "Rename" })[0])
    const name = screen.getByLabelText("Name")
    await user.clear(name)
    await user.type(name, "Work laptop")
    await user.click(screen.getByRole("button", { name: "Save" }))
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    })
    await user.type(within(stepUp).getByLabelText("Password"), "pw")
    keys = [{ ...keys[0], label: "Work laptop" }, keys[1]]
    await user.click(within(stepUp).getByRole("button", { name: "Confirm" }))
    expect(await screen.findByText("Work laptop")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Remove: Device key" }))
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Remove",
      })
    )
    await waitFor(() => expect(calls).toEqual(["delete k2"]))
    await waitFor(() =>
      expect(screen.queryByText("Device key")).not.toBeInTheDocument()
    )
  })
})

describe("LinkedProvidersPanel", () => {
  it("never invokes the sign-in callback from a link-only dialog", async () => {
    const onSignedIn = vi.fn()
    const navigate = vi.fn()
    const { user, client } = await renderSignedIn(
      <SignInDialog
        mode="link"
        open
        onOpenChange={() => {}}
        onSignedIn={onSignedIn}
        navigate={navigate}
      />,
      {
        "POST /api/v1/oidc/github/link/start": () =>
          json(200, { auth_url: "https://github.test/link" }),
      }
    )
    await user.click(
      await screen.findByRole("button", { name: "Link with GitHub" })
    )
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("https://github.test/link")
    )
    expect(onSignedIn).not.toHaveBeenCalled()
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  })

  it("lists linked providers and opens only available linking choices", async () => {
    const navigate = vi.fn()
    const called: string[] = []
    const { user, client } = await renderSignedIn(
      <LinkedProvidersPanel navigate={navigate} />,
      {
        "GET /api/v1/me": () =>
          profile({
            providers: [
              { provider: "github", email: null, linked_at: "2026-01-01" },
              { provider: "solana", email: null, linked_at: "2026-01-01" },
            ],
            solana_wallet: { address: "wallet-address", verified: true },
          }),
        "GET /api/v1/capabilities": () =>
          json(200, {
            external_login_providers: [
              {
                id: "github",
                name: "GitHub",
                supports_login: true,
                supports_link: true,
              },
              {
                id: "google",
                name: "Google",
                supports_login: true,
                supports_link: true,
              },
              {
                id: "no-link",
                name: "Sign-in only",
                supports_login: true,
                supports_link: false,
              },
            ],
            solana: { login: true },
          }),
        "POST /api/v1/oidc/google/link/start": (init) => {
          called.push(init.url)
          expect(new Headers(init.headers).get("Authorization")).toBeTruthy()
          return json(200, { auth_url: "https://google.test/link" })
        },
      }
    )
    expect(await screen.findByText("GitHub")).toBeInTheDocument()
    expect(screen.getByText("Solana")).toBeInTheDocument()
    expect(screen.queryByText("Google")).toBeNull()
    await user.click(
      screen.getByRole("button", { name: "Link a social login" })
    )
    const dialog = screen.getByRole("dialog", { name: "Link a social login" })
    expect(
      within(dialog).getByRole("button", { name: "Link with Google" })
    ).toBeInTheDocument()
    expect(within(dialog).queryByText(/GitHub|Sign-in only/)).toBeNull()
    expect(within(dialog).queryByRole("textbox")).toBeNull()
    expect(within(dialog).queryByLabelText("Password")).toBeNull()
    expect(
      within(dialog).queryByText(/Create account|Register|Forgot password/)
    ).toBeNull()
    await user.click(
      within(dialog).getByRole("button", { name: "Link with Google" })
    )
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("https://google.test/link")
    )
    expect(called).toEqual(["/api/v1/oidc/google/link/start"])
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  })

  it("links Solana from the link-only modal without signing in", async () => {
    const acquireSolanaSigner = vi.fn(async () => ({
      publicKey: "W",
      signMessage: vi.fn(async () => new Uint8Array(64).fill(1)),
    }))
    let wallet: unknown = null
    const calls: string[] = []
    const { user, client } = await renderSignedIn(
      <LinkedProvidersPanel acquireSolanaSigner={acquireSolanaSigner} />,
      {
        "GET /api/v1/me": () => profile({ solana_wallet: wallet }),
        "GET /api/v1/capabilities": () =>
          json(200, { external_login_providers: [], solana: { login: true } }),
        "POST /api/v1/solana/challenge": (init) => {
          calls.push(init.url)
          return json(200, { message: "m" })
        },
        "PUT /api/v1/me/solana-wallet": (init) => {
          calls.push(init.url)
          expect(new Headers(init.headers).get("Authorization")).toBeTruthy()
          wallet = { address: "W", verified: true }
          return json(200, wallet)
        },
      }
    )
    await user.click(
      await screen.findByRole("button", { name: "Link a social login" })
    )
    const dialog = screen.getByRole("dialog", { name: "Link a social login" })
    await user.click(
      within(dialog).getByRole("button", { name: "Link with Solana" })
    )
    await waitFor(() =>
      expect(calls).toEqual([
        "/api/v1/solana/challenge",
        "/api/v1/me/solana-wallet",
      ])
    )
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(await screen.findByText("Solana")).toBeInTheDocument()
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  })

  it("confirms unlinking and explains the last sign-in method", async () => {
    const { user } = await renderSignedIn(<LinkedProvidersPanel />, {
      "GET /api/v1/me": () =>
        profile({
          has_password: false,
          providers: [
            {
              provider: "github",
              email: null,
              linked_at: "2026-01-01T00:00:00Z",
            },
          ],
        }),
      "DELETE /api/v1/me/providers/github": () =>
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
      { "DELETE /api/v1/me": () => noContent() }
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
    for (const name of ["Social Logins", "Danger zone"])
      expect(await screen.findByText(name)).toBeInTheDocument()
    expect(screen.queryByText("Contact details")).toBeNull()
    expect(
      screen.getByRole("button", { name: "Change password" })
    ).toBeInTheDocument()
    const card = screen
      .getByRole("button", { name: "Change password" })
      .closest('[data-slot="card"]')
    expect(card?.parentElement).toHaveClass("grid", "gap-6")
    expect(card?.parentElement).not.toHaveClass("authui")
    expect(screen.queryByText("Active sessions")).not.toBeInTheDocument()
  })
})

describe("AccountProfile", () => {
  it("keeps the avatar and edit slot beside the username with a red logout action", async () => {
    const clientRef: { current: ReturnType<typeof createAuthClient> | null } = {
      current: null,
    }
    const before: string[] = []
    const onSignedOut = vi.fn()
    const { user, client } = await renderSignedIn(
      <AccountProfile
        avatar={<span>Avatar editor</span>}
        nameAction={<button>Edit username</button>}
        onSignOut={() =>
          before.push(clientRef.current?.getSnapshot().status ?? "unready")
        }
        onSignedOut={onSignedOut}
      >
        <span>Premium member</span>
      </AccountProfile>,
      { "DELETE /api/v1/logout": () => noContent() }
    )
    clientRef.current = client
    const heading = await screen.findByRole("heading", { name: "u1" })
    expect(heading.parentElement).toContainElement(
      screen.getByRole("button", { name: "Edit username" })
    )
    const logout = screen.getByRole("button", { name: "Logout" })
    expect(heading.parentElement).toContainElement(logout)
    expect(logout).toHaveClass("bg-destructive", "text-white", "ml-auto")
    expect(screen.getByText("Avatar editor")).toBeInTheDocument()
    await user.click(logout)
    await waitFor(() => expect(onSignedOut).toHaveBeenCalledOnce())
    expect(before).toEqual(["authenticated"])
    expect(client.getSnapshot().status).toBe("anonymous")
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
        "PUT /api/v1/me/solana-wallet": (init) => {
          linked.push(JSON.parse(String(init.body)))
          return json(200, { provider: "solana", address: "W", verified: true })
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
