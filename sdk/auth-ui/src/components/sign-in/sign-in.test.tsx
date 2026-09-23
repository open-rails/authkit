// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../../client/client.ts"
import { authError, json, stubFetch } from "../../client/testing.ts"
import { AuthUiProvider } from "../../provider.tsx"
import { AuthProvider } from "../../react/provider.tsx"
import { session, token } from "../../react/testing.tsx"
import { normalizeIdentifier } from "./identifier.ts"
import { LoginForm } from "./LoginForm.tsx"
import { RegisterForm } from "./RegisterForm.tsx"
import { SignInDialog } from "./SignInDialog.tsx"
import { VerifyLink } from "./VerifyLink.tsx"

// input-otp probes for password-manager overlays.
document.elementFromPoint ??= () => null

const capabilities = () =>
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
    password: { login: true },
    passwordless: { enabled: false },
    passkeys: { login: false },
    solana: { login: false },
    verification: { registration: "required" },
  })

const emailChallenge = (challenge = "ch-1") =>
  authError(403, "2fa_required", {
    user_id: "u1",
    challenge,
    method: "email",
    verification_id: "a***@x.test",
    default_factor: { id: "f-email", method: "email", is_default: true },
    available_factors: [{ id: "f-email", method: "email" }],
  })

function renderUi(ui: ReactNode, fetch: typeof globalThis.fetch) {
  const client = createAuthClient({ fetch })
  const view = render(
    <AuthProvider client={client} autoStart={false}>
      <AuthUiProvider>{ui}</AuthUiProvider>
    </AuthProvider>
  )
  return { client, ...view }
}

async function submitCredentials(
  user: ReturnType<typeof userEvent.setup>,
  root: Pick<typeof screen, "getByLabelText" | "getByRole"> = screen
) {
  await user.type(root.getByLabelText("Email or phone number"), "a@x.test")
  await user.type(root.getByLabelText("Password"), "pw-123456")
  await user.click(root.getByRole("button", { name: "Sign in" }))
}

describe("LoginForm", () => {
  it("offers a new code after a burned email code, then signs in", async () => {
    const user = userEvent.setup()
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities,
      "POST /api/v1/password/login": [emailChallenge()],
      "POST /api/v1/2fa/verify": [
        authError(400, "invalid_code"),
        session({ sub: "u1", sid: "s1" }),
      ],
      "POST /api/v1/2fa/challenge": () => emailChallenge("ch-2"),
    })
    renderUi(<LoginForm onSignedIn={onSignedIn} />, fetch)
    await submitCredentials(user)

    await screen.findByRole("heading", { name: "Verify it's you" })
    expect(screen.getByText("We sent a code to a***@x.test.")).toBeVisible()
    await user.type(screen.getByLabelText("Verification code"), "111111")

    await screen.findByText(/can't be used again/)
    expect(screen.queryByRole("button", { name: /Resend code/ })).toBeNull()
    await user.click(screen.getByRole("button", { name: "Send a new code" }))
    await screen.findByText("A new code is on its way.")
    expect(onSignedIn).not.toHaveBeenCalled()

    await user.type(screen.getByLabelText("Verification code"), "222222")
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledOnce())
    const verify = fetch.mock.calls.filter(([url]) =>
      String(url).endsWith("/2fa/verify")
    )
    expect(JSON.parse(String(verify[1][1]?.body))).toMatchObject({
      challenge: "ch-2",
      code: "222222",
    })
  })

  it("points legacy accounts at the reset form, prefilled", async () => {
    const user = userEvent.setup()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities,
      "POST /api/v1/password/login": [
        authError(403, "password_reset_required"),
      ],
      "POST /api/v1/password/reset/request": () => json(202, {}),
    })
    renderUi(<LoginForm />, fetch)
    await submitCredentials(user)
    await user.click(
      await screen.findByRole("button", { name: "Reset your password" })
    )
    expect(screen.getByLabelText("Email or phone number")).toHaveValue(
      "a@x.test"
    )
    await user.click(screen.getByRole("button", { name: "Send reset link" }))
    await screen.findByRole("heading", { name: "Check your email" })
  })
})

describe("SignInDialog", () => {
  it("holds the session behind backup codes until acknowledged", async () => {
    const user = userEvent.setup()
    const onSignedIn = vi.fn()
    const onOpenChange = vi.fn()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities,
      "POST /api/v1/password/login": [
        authError(403, "2fa_enrollment_required", {
          user_id: "u1",
          allowed_methods: ["totp", "email"],
          enrollment_token: "enroll-tok",
          enrollment_expires_in: 600,
        }),
      ],
      "POST /api/v1/user/2fa": ({ body }) =>
        JSON.parse(String(body)).code
          ? json(200, {
              enabled: true,
              method: "totp",
              backup_codes: ["AAAA1111", "BBBB2222"],
              access_token: token({ sub: "u1", sid: "s1" }),
            })
          : json(200, {
              method: "totp",
              secret: "S3CR3T",
              otpauth_uri: "otpauth://totp/x?secret=S3CR3T",
            }),
    })
    const { client } = renderUi(
      <SignInDialog open onOpenChange={onOpenChange} onSignedIn={onSignedIn} />,
      fetch
    )
    await screen.findByRole("button", { name: "Continue with GitHub" })
    await submitCredentials(user, within(screen.getByRole("tabpanel")))

    await screen.findByRole("heading", {
      name: "Set up two-factor authentication",
    })
    expect(screen.queryByRole("tablist")).toBeNull()
    expect(
      screen.getByRole("radio", { name: /Authenticator app/ })
    ).toBeChecked()
    await user.click(
      screen.getByRole("button", { name: "Set up authenticator" })
    )
    await screen.findByText("S3CR3T")
    await user.type(screen.getByLabelText("Verification code"), "123456")

    await screen.findByRole("heading", { name: "Save your backup codes" })
    expect(
      screen.getAllByTestId("backup-code").map((c) => c.textContent)
    ).toEqual(["AAAA1111", "BBBB2222"])
    expect(client.getSnapshot().status).toBe("authenticated")
    expect(screen.queryByRole("button", { name: "Close" })).toBeNull()
    await user.keyboard("{Escape}")
    expect(onOpenChange).not.toHaveBeenCalled()
    expect(onSignedIn).not.toHaveBeenCalled()

    await user.click(
      screen.getByRole("button", { name: "I've saved my backup codes" })
    )
    expect(onSignedIn).toHaveBeenCalledWith({ returnTo: undefined })
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})

describe("RegisterForm", () => {
  it("shows availability and server errors on their fields", async () => {
    const user = userEvent.setup()
    const fetch = stubFetch({
      "GET /api/v1/capabilities": capabilities,
      "GET /api/v1/register/availability": ({ url }) => {
        const q = new URL(url, "http://x").searchParams
        return json(200, {
          ...(q.get("username") && {
            username:
              q.get("username") === "taken"
                ? { available: false, error: "username_in_use" }
                : { available: true },
          }),
          ...(q.get("email") && { email: { available: true } }),
        })
      },
      "POST /api/v1/register": [authError(409, "email_in_use")],
    })
    renderUi(<RegisterForm />, fetch)
    await user.type(screen.getByLabelText("Email or phone number"), "a@x.test")
    await user.type(screen.getByLabelText("Username"), "taken")
    await screen.findByText("This username is already in use.")

    await user.clear(screen.getByLabelText("Username"))
    await user.type(screen.getByLabelText("Username"), "fresh")
    await waitFor(() =>
      expect(screen.queryByText("This username is already in use.")).toBeNull()
    )
    await user.type(screen.getByLabelText("Password"), "short")
    await user.click(screen.getByRole("button", { name: "Register" }))
    expect(
      screen.getByText("Password must be at least 8 characters")
    ).toBeVisible()

    await user.type(screen.getByLabelText("Password"), "-long-enough")
    await user.click(screen.getByRole("button", { name: "Register" }))
    const email = screen.getByLabelText("Email or phone number")
    await waitFor(() => expect(email).toHaveAttribute("aria-invalid", "true"))
    expect(screen.getByText("This email is already in use.")).toBeVisible()
  })

  it("validates against the advertised username and password policy", async () => {
    const user = userEvent.setup()
    const register = vi.fn(() => json(202, { next_action: "verify_email" }))
    const fetch = stubFetch({
      "GET /api/v1/capabilities": () =>
        json(200, {
          registration: { mode: "open", invite_token_required: false },
          external_login_providers: [],
          username: {
            min_length: 4,
            max_length: 30,
            pattern: "^[A-Za-z][A-Za-z0-9_]*$",
          },
          password: { login: true, min_length: 12, require_digit: true },
          passwordless: { enabled: false },
          passkeys: { login: false },
          solana: { login: false },
          verification: { registration: "required" },
        }),
      "GET /api/v1/register/availability": () => json(200, {}),
      "POST /api/v1/register": register,
    })
    renderUi(<RegisterForm />, fetch)
    await screen.findByText("Use at least 12 characters.")
    await user.type(screen.getByLabelText("Email or phone number"), "a@x.test")
    await user.type(screen.getByLabelText("Username"), "1ab")
    await user.type(screen.getByLabelText("Password"), "long-enough")
    await user.click(screen.getByRole("button", { name: "Register" }))
    expect(
      screen.getByText("Password must be at least 12 characters")
    ).toBeVisible()
    expect(
      screen.getByText("Username must be at least 4 characters.")
    ).toBeVisible()

    await user.type(screen.getByLabelText("Username"), "c")
    await user.type(screen.getByLabelText("Password"), "-pw")
    expect(
      screen.getByText("Password doesn't meet the requirements.")
    ).toBeVisible()
    expect(screen.getByText("Username must start with a letter.")).toBeVisible()
    expect(register).not.toHaveBeenCalled()
  })
})

describe("VerifyLink", () => {
  it("confirms the link token once and reports the new session", async () => {
    const user = userEvent.setup()
    const navigate = vi.fn()
    const onVerified = vi.fn()
    const confirm = vi.fn(() => session({ sub: "u1", sid: "s1" }))
    const fetch = stubFetch({ "POST /api/v1/verify/confirm": confirm })
    renderUi(
      <VerifyLink token="tok-1" navigate={navigate} onVerified={onVerified} />,
      fetch
    )
    await screen.findByText("Verified and signed in.")
    expect(onVerified).toHaveBeenCalledWith({
      signedIn: true,
      returnTo: undefined,
    })
    expect(confirm).toHaveBeenCalledOnce()
    const body = fetch.mock.calls.find(([url]) =>
      String(url).endsWith("/verify/confirm")
    )?.[1]?.body
    expect(JSON.parse(String(body))).toEqual({ token: "tok-1" })
    await user.click(screen.getByRole("button", { name: "Continue" }))
    expect(navigate).toHaveBeenCalledWith("/")
  })

  it("explains a dead or missing link", async () => {
    const fetch = stubFetch({
      "POST /api/v1/verify/confirm": () =>
        authError(400, "invalid_or_expired_token"),
    })
    const { unmount } = renderUi(
      <VerifyLink token="stale" navigate={vi.fn()} />,
      fetch
    )
    await screen.findByText("This link is invalid or has expired.")
    unmount()
    renderUi(<VerifyLink navigate={vi.fn()} />, stubFetch({}))
    expect(
      screen.getByText("This link is invalid or has expired.")
    ).toBeVisible()
  })
})

describe("normalizeIdentifier", () => {
  it("turns national numbers into E.164 with the default country", () => {
    expect(normalizeIdentifier(" a@x.test ")).toBe("a@x.test")
    expect(normalizeIdentifier("(415) 555-0100", "US")).toBe("+14155550100")
    expect(normalizeIdentifier("07700 900123", "GB")).toBe("+447700900123")
    expect(normalizeIdentifier("+49 30 1234567", "US")).toBe("+49301234567")
    expect(normalizeIdentifier("0049 30 1234567")).toBe("+49301234567")
    expect(normalizeIdentifier("someone")).toBe("someone")
  })
})
