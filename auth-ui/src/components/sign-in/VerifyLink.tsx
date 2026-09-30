import {
  AlertCircleIcon,
  CheckmarkCircle02Icon,
} from "@hugeicons/core-free-icons"
import { useEffect, useRef, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import { useVerifyLink } from "#authui/react/providers"
import { useLogin } from "#authui/react/useLogin"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { Spinner } from "#authui/ui/spinner"
import { LoginSteps } from "./LoginSteps.tsx"
import { StepHeader } from "./parts.tsx"

export type VerifyLinkProps = {
  // From the verification link: readLinkFragment(location.hash)?.token.
  token?: string | null
  // Leaves the landing route; use the router's replace navigation.
  navigate: (to: string) => void
  // Where "Continue" goes without a returnTo.
  fallbackPath?: string
  onVerified?: (result: { signedIn: boolean; returnTo?: string }) => void
  defaultPhoneCountry?: string
  // Wraps the pending/result UI, e.g. in the app's page shell.
  layout?: (children: ReactNode) => ReactNode
  className?: string
}

// AuthKit's email/phone verification link landing (Frontend.VerifyPath):
// confirms the token once and finishes any sign-in continuation in place.
export function VerifyLink({
  token,
  navigate,
  fallbackPath = "/",
  onVerified,
  defaultPhoneCountry,
  layout = (c) => c,
  className,
}: VerifyLinkProps) {
  const { t, error: describe } = useMessages()
  const state = useVerifyLink(token)
  const login = useLogin({
    onSignedIn: ({ returnTo }) => navigate(returnTo ?? fallbackPath),
  })
  const { resume } = login

  const reported = useRef(false)
  const onVerifiedRef = useRef(onVerified)
  useEffect(() => {
    onVerifiedRef.current = onVerified
  })
  useEffect(() => {
    if (state.status === "continuation") resume(state.continuation)
    if (state.status !== "verified" || reported.current) return
    reported.current = true
    onVerifiedRef.current?.({
      signedIn: state.signedIn,
      returnTo: state.returnTo,
    })
  }, [state, resume])

  let body: ReactNode
  if (state.status === "error") {
    body = (
      <div className="flex flex-col gap-5" role="alert">
        <StepHeader
          icon={AlertCircleIcon}
          title={t("verify.errorTitle")}
          description={describe(state.error)}
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
  } else if (state.status === "verified") {
    body = (
      <div className="flex flex-col gap-5" role="status">
        <StepHeader
          icon={CheckmarkCircle02Icon}
          title={t("verify.success")}
          description={state.signedIn ? t("verify.successSignedIn") : undefined}
        />
        <Button
          size="lg"
          className="w-full"
          onClick={() => navigate(state.returnTo ?? fallbackPath)}
        >
          {t("common.continue")}
        </Button>
      </div>
    )
  } else if (login.state.step !== "credentials") {
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
        {t("verify.verifying")}
      </div>
    )
  }
  return (
    <AuthUiRoot className={className}>
      {layout(<div className="mx-auto w-full max-w-sm px-4 py-10">{body}</div>)}
    </AuthUiRoot>
  )
}
