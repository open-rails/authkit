import {
  AppleIcon,
  DiscordIcon,
  FingerPrintIcon,
  GithubIcon,
  GoogleIcon,
  Login01Icon,
  NewTwitterIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useState } from "react"

import type { SignInResult } from "#authui/client/authResult"
import { AuthKitError } from "#authui/client/errors"
import type { AgreementRef } from "#authui/client/types"
import { useMessages } from "#authui/i18n/context"
import { useAuthClient, useCapabilities } from "#authui/react/context"
import { Button } from "#authui/ui/button"
import { Spinner } from "#authui/ui/spinner"
import {
  resolveProviders,
  type ProvidersOption,
  type SignInMode,
  type SolanaSlot,
} from "./host.ts"
import { FormAlert, OrSeparator } from "./parts.tsx"

const BRAND = {
  apple: AppleIcon,
  discord: DiscordIcon,
  github: GithubIcon,
  google: GoogleIcon,
  twitter: NewTwitterIcon,
  x: NewTwitterIcon,
}

export function ProviderButtons({
  mode,
  providers,
  renderSolana,
  onOutcome,
  returnTo,
  inviteCode,
  agreements,
  disabled,
  onPasskey,
}: {
  mode: SignInMode
  providers?: ProvidersOption
  renderSolana?: SolanaSlot
  onOutcome: (result: SignInResult) => void
  returnTo?: string
  inviteCode?: string
  // The documents a sign-up through the provider accepts.
  agreements?: AgreementRef[]
  disabled?: boolean
  // Passkey sign-in, offered first when set.
  onPasskey?: () => void
}) {
  const { t, error: describe } = useMessages()
  const client = useAuthClient()
  const { capabilities } = useCapabilities()
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState<AuthKitError | null>(null)
  const list = resolveProviders(
    capabilities?.external_login_providers ?? [],
    mode,
    providers
  )
  const solana = renderSolana?.({
    mode,
    onOutcome,
    disabled: !!disabled || pending !== null,
  })
  if (!list.length && !solana && !onPasskey) return null

  // No await before signInWithPopup: the window must open inside the click.
  const start = async (id: string) => {
    setError(null)
    setPending(id)
    try {
      const opts = { returnTo, inviteCode, agreements }
      const out = await client.signInWithPopup(id, opts)
      if (out.ok) return onOutcome(out.result)
      if (out.reason === "blocked") {
        await client.signInWithRedirect(id, opts)
        return
      }
      if (out.reason === "closed") return
      const code =
        out.reason === "provider_error"
          ? out.code
          : out.reason === "session_changed"
            ? out.reason
            : `popup_${out.reason}`
      setError(new AuthKitError(0, { type: "local", code, message: code }))
    } finally {
      setPending(null)
    }
  }

  const label = (name: string) =>
    mode === "login"
      ? t("signIn.continueWith", { provider: name })
      : t("register.signUpWith", { provider: name })

  return (
    <div className="flex flex-col gap-4">
      <OrSeparator label={t("common.or")} />
      {error && <FormAlert>{describe(error)}</FormAlert>}
      <div className="flex flex-col gap-2.5">
        {onPasskey && (
          <Button
            type="button"
            variant="outline"
            size="lg"
            className="w-full"
            disabled={disabled || pending !== null}
            onClick={onPasskey}
          >
            <HugeiconsIcon icon={FingerPrintIcon} strokeWidth={2} />
            {t("signIn.withPasskey")}
          </Button>
        )}
        {list.map((p) => (
          <Button
            key={p.id}
            type="button"
            variant="outline"
            size="lg"
            className="w-full"
            disabled={disabled || pending !== null}
            onClick={() => void start(p.id)}
          >
            {pending === p.id ? (
              <Spinner />
            ) : (
              (p.icon ?? (
                <HugeiconsIcon
                  icon={BRAND[p.id as keyof typeof BRAND] ?? Login01Icon}
                  strokeWidth={2}
                />
              ))
            )}
            {pending === p.id ? t("signIn.connecting") : label(p.name)}
          </Button>
        ))}
        {solana}
      </div>
    </div>
  )
}
