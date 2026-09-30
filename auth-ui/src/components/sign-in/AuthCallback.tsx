import { AlertCircleIcon } from "@hugeicons/core-free-icons"
import { useEffect, useRef, type ReactNode } from "react"

import type { RedirectResult } from "#authui/client/client"
import { useMessages } from "#authui/i18n/context"
import { useOidcCallback } from "#authui/react/providers"
import { useLogin } from "#authui/react/useLogin"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { Spinner } from "#authui/ui/spinner"
import { LoginSteps } from "./LoginSteps.tsx"
import { StepHeader } from "./parts.tsx"

export type AuthCallbackProps = {
  // Leaves the callback route; use the router's replace navigation.
  navigate: (to: string) => void
  // Where to go without a returnTo, or after an abandoned continuation.
  fallbackPath?: string
  onSignedIn?: (result: { returnTo?: string; provider?: string }) => void
  onLinked?: (result: { provider?: string }) => void
  defaultPhoneCountry?: string
  // Wraps the pending/continuation/error UI, e.g. in the app's page shell.
  layout?: (children: ReactNode) => ReactNode
  className?: string
}

// The OIDC redirect route: consumes AuthKit's fragment once, finishes 2FA and
// other continuations in place, then navigates on.
export function AuthCallback({
  navigate,
  fallbackPath = "/",
  onSignedIn,
  onLinked,
  defaultPhoneCountry,
  layout = (c) => c,
  className,
}: AuthCallbackProps) {
  const { t, error: describe } = useMessages()
  const host = useRef({ navigate, onSignedIn, onLinked, fallbackPath })
  useEffect(() => {
    host.current = { navigate, onSignedIn, onLinked, fallbackPath }
  })
  const provider = useRef<string | undefined>(undefined)
  const login = useLogin({
    onSignedIn: ({ returnTo }) => {
      host.current.onSignedIn?.({ returnTo, provider: provider.current })
      host.current.navigate(returnTo ?? host.current.fallbackPath)
    },
  })
  const { resume } = login
  const handle = (result: RedirectResult | null) => {
    const h = host.current
    if (!result) return h.navigate(h.fallbackPath)
    switch (result.kind) {
      case "session":
        h.onSignedIn?.({ returnTo: result.returnTo, provider: result.provider })
        return h.navigate(result.returnTo ?? h.fallbackPath)
      case "linked":
        h.onLinked?.({ provider: result.provider })
        return h.navigate(h.fallbackPath)
      case "error":
        return
      default:
        resume(result)
    }
  }
  const { result, error } = useOidcCallback({ onResult: handle })

  // Backing out of a continuation leaves the route.
  const entered = useRef(false)
  const step = login.state.step
  useEffect(() => {
    if (step !== "credentials") entered.current = true
    else if (entered.current) host.current.navigate(host.current.fallbackPath)
  }, [step])

  const failure = error ?? (result?.kind === "error" ? result.code : null)
  let body: ReactNode
  if (failure) {
    body = (
      <div className="flex flex-col gap-5" role="alert">
        <StepHeader
          icon={AlertCircleIcon}
          title={t("callback.errorTitle")}
          description={describe(failure)}
        />
        <Button
          size="lg"
          className="w-full"
          onClick={() => navigate(fallbackPath)}
        >
          {t("common.goHome")}
        </Button>
      </div>
    )
  } else if (step !== "credentials") {
    body = (
      <LoginSteps
        controller={login}
        defaultPhoneCountry={defaultPhoneCountry}
      />
    )
  } else {
    body = (
      <div
        role="status"
        className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground"
      >
        <Spinner />
        {t("callback.completing")}
      </div>
    )
  }
  return (
    <AuthUiRoot className={className}>
      {layout(<div className="mx-auto w-full max-w-sm px-4 py-10">{body}</div>)}
    </AuthUiRoot>
  )
}
