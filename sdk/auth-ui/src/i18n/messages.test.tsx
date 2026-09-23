// @vitest-environment jsdom
import "../test/dom.ts"

import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { AuthKitError } from "../client/errors.ts"
import { AUTH_ERROR_STATUS } from "../client/generated/error-codes.ts"
import { AuthUiProvider } from "../provider.tsx"
import { de } from "../locales/de.ts"
import { en } from "../locales/en.ts"
import { es } from "../locales/es.ts"
import { ja } from "../locales/ja.ts"
import { ko } from "../locales/ko.ts"
import { zh } from "../locales/zh.ts"
import { useMessages } from "./context.ts"
import {
  createTranslator,
  defineMessages,
  resolveMessages,
  type MessageKey,
  type MessageVars,
} from "./messages.ts"

function Probe({ k, vars }: { k: MessageKey; vars?: MessageVars }) {
  const { t } = useMessages()
  return <span data-testid="out">{t(k, vars)}</span>
}

function ErrorProbe({ error }: { error: unknown }) {
  return <span data-testid="out">{useMessages().error(error)}</span>
}

const out = () => screen.getByTestId("out").textContent

describe("messages", () => {
  it("defaults to English without a provider", () => {
    render(<Probe k="signIn.title" />)
    expect(out()).toBe("Sign in")
  })

  it("uses the locale bundle and falls back to English per key", () => {
    const partial = defineMessages({ signIn: { title: "Anmelden!" } })
    render(
      <AuthUiProvider messages={partial}>
        <Probe k="signIn.title" />
      </AuthUiProvider>
    )
    expect(out()).toBe("Anmelden!")

    const messages = resolveMessages(partial)
    expect(messages.signIn.forgotPassword).toBe(en.signIn.forgotPassword)
  })

  it("layers bundles with later entries winning and ignores empty strings", () => {
    const messages = resolveMessages([
      de,
      { signIn: { title: "Custom" }, register: { title: "" } },
    ])
    expect(messages.signIn.title).toBe("Custom")
    expect(messages.register.title).toBe(de.register?.title)
    expect(messages.common.cancel).toBe(de.common?.cancel)
  })

  it("interpolates named variables and leaves unknown ones", () => {
    render(
      <AuthUiProvider messages={{ common: { resendIn: "{seconds}s / {x}" } }}>
        <Probe k="common.resendIn" vars={{ seconds: 12 }} />
      </AuthUiProvider>
    )
    expect(out()).toBe("12s / {x}")
  })

  it("prefers the host t override and falls through when it has nothing", () => {
    const t = (key: string, vars?: MessageVars) =>
      key === "signIn.title" ? `host:${vars?.n ?? ""}` : key
    const { rerender } = render(
      <AuthUiProvider t={t}>
        <Probe k="signIn.title" vars={{ n: 1 }} />
      </AuthUiProvider>
    )
    expect(out()).toBe("host:1")
    rerender(
      <AuthUiProvider t={t}>
        <Probe k="signIn.submit" />
      </AuthUiProvider>
    )
    expect(out()).toBe("Sign in")
  })

  it("maps AuthKit error codes with a generic fallback", () => {
    const err = new AuthKitError(429, {
      type: "rate_limit_error",
      code: "rate_limited",
      message: "slow down",
    })
    render(
      <AuthUiProvider messages={ja}>
        <ErrorProbe error={err} />
      </AuthUiProvider>
    )
    expect(out()).toBe(ja.errors?.rate_limited)

    const tr = createTranslator(resolveMessages())
    expect(tr.error("no_such_code")).toBe(en.errors.generic)
    expect(tr.error(new Error("boom"))).toBe(en.errors.generic)
    expect(tr.error(new TypeError("Failed to fetch"))).toBe(en.errors.network)
    expect(tr.error({ code: "invalid_credentials" })).toBe(
      en.errors.invalid_credentials
    )
  })

  it("routes error codes through the host override", () => {
    const tr = createTranslator(resolveMessages(), (key) =>
      key === "errors.user_banned" ? "banned by host" : undefined
    )
    expect(tr.error("user_banned")).toBe("banned by host")
  })
})

describe("locale bundles", () => {
  const flatten = (tree: object, prefix = ""): Record<string, string> =>
    Object.fromEntries(
      Object.entries(tree).flatMap(([k, v]) =>
        typeof v === "string"
          ? [[prefix + k, v]]
          : Object.entries(flatten(v, `${prefix}${k}.`))
      )
    )
  const english = flatten(en)
  const placeholders = (s: string) =>
    [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()

  it.each(Object.entries({ de, es, ja, ko, zh }))(
    "%s only uses English keys with matching placeholders",
    (_, bundle) => {
      for (const [key, value] of Object.entries(flatten(bundle))) {
        expect(english, key).toHaveProperty([key])
        expect(placeholders(value), key).toEqual(placeholders(english[key]))
      }
    }
  )

  it("keys errors only by codes in the pinned AuthKit contract", () => {
    // generic/network are local fallbacks; access_denied is the OIDC redirect error.
    const local = new Set(["generic", "network", "access_denied"])
    for (const code of Object.keys(en.errors)) {
      if (!local.has(code))
        expect(AUTH_ERROR_STATUS, code).toHaveProperty([code])
    }
  })

  it("has English copy for the codes the flows branch on", () => {
    const codes = [
      "invalid_credentials",
      "2fa_required",
      "2fa_enrollment_required",
      "verification_required",
      "account_recovery_required",
      "password_reset_required",
      "step_up_required",
      "rate_limited",
      "user_banned",
      "invalid_or_expired_code",
    ]
    for (const code of codes) expect(en.errors).toHaveProperty([code])
  })
})
