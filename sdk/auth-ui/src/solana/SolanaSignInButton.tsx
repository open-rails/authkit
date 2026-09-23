import { cn } from "cn"
import { useId } from "react"

import type { AuthOutcome } from "../client/client.ts"
import { useMessages } from "../i18n/context.ts"
import type { Translator } from "../i18n/messages.ts"
import { useAuthClient } from "../react/context.ts"
import { Button } from "../ui/button.tsx"
import { Spinner } from "../ui/spinner.tsx"
import { isSolanaWalletError, type WalletAdapterLike } from "./core.ts"
import { useSolanaAuth } from "./useSolanaAuth.ts"

export type SolanaSignInButtonProps = {
  // wallet-adapter's useWallet(), or any WalletAdapterLike.
  wallet: WalletAdapterLike | null | undefined
  // Open the wallet picker; sign-in resumes once a wallet connects.
  onConnectRequest?: () => void
  // Pass the renderSolana slot's onOutcome so 2FA etc. continue in the form.
  onOutcome: (outcome: AuthOutcome) => void
  mode?: "login" | "register"
  // Username for an account created by this sign-in.
  username?: string
  disabled?: boolean
  className?: string
}

function walletError(m: Translator, err: unknown): string {
  if (!isSolanaWalletError(err)) return m.error(err)
  switch (err.reason) {
    case "not_connected":
      return m.t("solana.errors.not_connected")
    case "unsupported":
      return m.t("solana.errors.unsupported")
    case "rejected":
      return m.t("solana.errors.rejected")
    case "invalid_signature":
      return m.t("solana.errors.invalid_signature")
    case "busy":
      return m.t("solana.errors.busy")
  }
}

function SolanaMark() {
  const id = useId()
  return (
    <svg viewBox="0 0 397.7 311.7" className="size-4" aria-hidden="true">
      <defs>
        <linearGradient
          id={id}
          x1="360.9"
          y1="351.5"
          x2="141.2"
          y2="-69.3"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#00ffa3" />
          <stop offset="1" stopColor="#dc1fff" />
        </linearGradient>
      </defs>
      <path
        fill={`url(#${id})`}
        d="M64.6 237.9a13 13 0 0 1 9.2-3.8h317.4c5.8 0 8.7 7 4.6 11.1l-62.7 62.7a13 13 0 0 1-9.2 3.8H6.5c-5.8 0-8.7-7-4.6-11.1zM64.6 3.8A13.4 13.4 0 0 1 73.8 0h317.4c5.8 0 8.7 7 4.6 11.1l-62.7 62.7a13 13 0 0 1-9.2 3.8H6.5c-5.8 0-8.7-7-4.6-11.1zM333.1 120.1a13 13 0 0 0-9.2-3.8H6.5c-5.8 0-8.7 7-4.6 11.1l62.7 62.7a13 13 0 0 0 9.2 3.8h317.4c5.8 0 8.7-7 4.6-11.1z"
      />
    </svg>
  )
}

// Styled wallet sign-in for LoginForm/SignInDialog's renderSolana slot.
export function SolanaSignInButton({
  wallet,
  onConnectRequest,
  onOutcome,
  mode = "login",
  username,
  disabled,
  className,
}: SolanaSignInButtonProps) {
  const messages = useMessages()
  const { t } = messages
  const solana = useSolanaAuth(useAuthClient(), wallet, {
    onConnectRequest,
    onSignIn: onOutcome,
    username,
  })
  const busy = solana.busy === "signIn"
  const waiting = busy || solana.awaitingWallet === "signIn"
  const name = t("solana.provider")
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Button
        type="button"
        variant="outline"
        size="lg"
        className="w-full"
        disabled={disabled || busy}
        onClick={() => void solana.signIn()}
      >
        {waiting ? <Spinner /> : <SolanaMark />}
        {waiting
          ? t("signIn.connecting")
          : mode === "login"
            ? t("signIn.continueWith", { provider: name })
            : t("register.signUpWith", { provider: name })}
      </Button>
      {solana.error != null && (
        <p role="alert" className="text-center text-xs text-destructive">
          {walletError(messages, solana.error)}
        </p>
      )}
    </div>
  )
}
