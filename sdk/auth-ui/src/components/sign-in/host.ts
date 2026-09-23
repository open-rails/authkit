import type { ReactNode } from "react"
import { useCallback, useEffect, useRef } from "react"

import type { AuthOutcome } from "#authui/client/client"
import type { ExternalLoginProvider } from "#authui/client/types"

export type SignInMode = "login" | "register"

export type SignInProvider = {
  id: string
  name: string
  icon?: ReactNode
}

// A list replaces /capabilities; a function edits it (reorder, add icons).
export type ProvidersOption =
  | readonly SignInProvider[]
  | ((fromCapabilities: SignInProvider[], mode: SignInMode) => SignInProvider[])

// Lets hosts add wallet sign-in without the root entry importing ./solana.
export type SolanaSlot = (ctx: {
  mode: SignInMode
  // Feed the wallet outcome back so 2FA and other continuations run here.
  onOutcome: (outcome: AuthOutcome) => void
  disabled: boolean
}) => ReactNode

export type SignedInResult = { returnTo?: string }

export type SignInHostProps = {
  // Sent to AuthKit for provider sign-in and handed back after sign-in.
  returnTo?: string
  // Called with returnTo after sign-in when one is known.
  navigate?: (to: string) => void
  // Fires once the session exists and any backup codes were acknowledged.
  onSignedIn?: (result: SignedInResult) => void
  // ISO country used for phone numbers typed without a +country code.
  defaultPhoneCountry?: string
  providers?: ProvidersOption
  renderSolana?: SolanaSlot
  accountInviteToken?: string
}

export function resolveProviders(
  fromCaps: readonly ExternalLoginProvider[],
  mode: SignInMode,
  option: ProvidersOption | undefined
): SignInProvider[] {
  const available = fromCaps
    .filter((p) =>
      mode === "login" ? p.supports_login : p.supports_registration
    )
    .map((p) => ({ id: p.id, name: p.name || p.id }))
  if (!option) return available
  return typeof option === "function" ? option(available, mode) : [...option]
}

// onSignedIn, then navigate(returnTo) when there is somewhere to go.
export function useSignedIn(
  host: Pick<SignInHostProps, "onSignedIn" | "navigate" | "returnTo">
) {
  const latest = useRef(host)
  useEffect(() => {
    latest.current = host
  })
  return useCallback((result: SignedInResult) => {
    const { onSignedIn, navigate, returnTo } = latest.current
    const target = result.returnTo ?? returnTo
    onSignedIn?.({ returnTo: target })
    if (target && navigate) navigate(target)
  }, [])
}
