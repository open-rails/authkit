import { AlertCircleIcon } from "@hugeicons/core-free-icons"
import { useEffect, useRef, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import { useLogin } from "#authui/react/useLogin"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { Spinner } from "#authui/ui/spinner"
import { LoginSteps } from "./LoginSteps.tsx"
import { StepHeader } from "./parts.tsx"

export type PasswordlessLinkProps = {
  // From the emailed link: readLinkFragment(location.hash)?.token.
  token?: string | null
  // Leaves the landing route; use the router's replace navigation.
  navigate: (to: string) => void
  // Where a finished sign-in goes without a returnTo, and where backing out
  // of a step goes.
  fallbackPath?: string
  onSignedIn?: (result: { returnTo?: string }) => void
  defaultPhoneCountry?: string
  // Wraps the pending/result UI, e.g. in the app's page shell.
  layout?: (children: ReactNode) => ReactNode
  className?: string
}

// AuthKit's emailed sign-in link landing (Frontend.PasswordlessPath): spends
// the token once and finishes any later step in place (a second factor, a new
// device, restoring a deleted account).
export function PasswordlessLink({
  token,
  navigate,
  fallbackPath = "/",
  onSignedIn,
  defaultPhoneCountry,
  layout = (c) => c,
  className,
}: PasswordlessLinkProps) {
  const { t, error: describe } = useMessages()
  const host = useRef({ navigate, onSignedIn, fallbackPath })
  useEffect(() => {
    host.current = { navigate, onSignedIn, fallbackPath }
  })
  const login = useLogin({
    onSignedIn: ({ returnTo }) => {
      host.current.onSignedIn?.({ returnTo })
      host.current.navigate(returnTo ?? host.current.fallbackPath)
    },
  })
  const { confirmLink, error } = login

  const started = useRef(false)
  useEffect(() => {
    if (!token || started.current) return
    started.current = true
    void confirmLink(token)
  }, [token, confirmLink])

  // Backing out of a step leaves the route.
  const entered = useRef(false)
  const step = login.state.step
  useEffect(() => {
    if (step !== "credentials") entered.current = true
    else if (entered.current) host.current.navigate(host.current.fallbackPath)
  }, [step])

  const failure = error ?? (token ? null : { code: "invalid_link" })
  let body: ReactNode
  if (step !== "credentials") {
    body = (
      <LoginSteps
        controller={login}
        defaultPhoneCountry={defaultPhoneCountry}
      />
    )
  } else if (failure) {
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
