import { AlertCircleIcon } from "@hugeicons/core-free-icons"
import { useEffect, useRef, useState, type ReactNode } from "react"

import { errorMetadata } from "#authui/client/errors"
import type { Agreement, OAuthAuthorizationRequest } from "#authui/client/types"
import { StepUpProvider } from "#authui/components/account/step-up"
import { useStepUpGuard } from "#authui/components/account/step-up-context"
import { useMessages } from "#authui/i18n/context"
import { useAuthClient } from "#authui/react/context"
import { useAuth } from "#authui/react/useAuth"
import { AuthUiRoot } from "#authui/scope"
import { Spinner } from "#authui/ui/spinner"
import { AgreementsForm } from "./NetworkSteps.tsx"
import { StepHeader } from "./parts.tsx"
import { SignInPanel, type SignInPanelProps } from "./SignInPanel.tsx"

export type OAuthAuthorizeProps = Omit<SignInPanelProps, "description"> & {
  // The pending request; default: ?authorization= on this page.
  authorization?: string
  // Leaves for the client's redirect URI. Default: location.assign.
  redirect?: (url: string) => void
  // Wraps the pending/error UI, e.g. in the app's page shell.
  layout?: (children: ReactNode) => ReactNode
}

// The page at Frontend.AuthorizePath: signs the user in (second factors and
// a step-up included) for an OAuth client's authorization request, then
// sends the browser back to the client with its code. prompt=none with
// nobody signed in returns login_required without any UI.
export function OAuthAuthorize(props: OAuthAuthorizeProps) {
  return (
    <StepUpProvider>
      <Authorize {...props} />
    </StepUpProvider>
  )
}

function Authorize({
  authorization,
  redirect = (url) => location.assign(url),
  layout = (c) => c,
  className,
  ...signIn
}: OAuthAuthorizeProps) {
  const { t, error: describe } = useMessages()
  const client = useAuthClient()
  const auth = useAuth()
  const guard = useStepUpGuard()
  const id =
    authorization ??
    new URLSearchParams(globalThis.location?.search).get("authorization") ??
    ""
  const [request, setRequest] = useState<OAuthAuthorizationRequest | null>(null)
  const [failure, setFailure] = useState<unknown>(null)
  // The client's agreements the user has yet to accept.
  const [needed, setNeeded] = useState<Agreement[] | null>(null)
  const [accepting, setAccepting] = useState(false)
  const [acceptError, setAcceptError] = useState<unknown>(null)
  const answered = useRef(false)
  const leave = useRef(redirect)
  useEffect(() => {
    leave.current = redirect
  })

  useEffect(() => {
    const ctl = new AbortController()
    client.getOAuthAuthorization(id, ctl.signal).then(setRequest, (err) => {
      if (!ctl.signal.aborted) setFailure(err)
    })
    return () => ctl.abort()
  }, [client, id])

  const status = auth.status
  useEffect(() => {
    if (!request || needed || answered.current) return
    const none = request.prompt.includes("none")
    let answer: Promise<{ redirect_to: string }> | null = null
    if (status === "signed_in")
      answer = none
        ? client.approveOAuthAuthorization(id)
        : guard(() => client.approveOAuthAuthorization(id))
    else if (status === "signed_out" && none)
      answer = client.declineOAuthAuthorization(id, "login_required")
    if (!answer) return
    answered.current = true
    answer.then(
      ({ redirect_to }) => leave.current(redirect_to),
      (err: unknown) => {
        const code = (err as { code?: string }).code
        // prompt=none cannot step up: the client hears interaction_required.
        if (none && code === "step_up_required")
          return client
            .declineOAuthAuthorization(id, "interaction_required")
            .then(({ redirect_to }) => leave.current(redirect_to), setFailure)
        answered.current = false
        const required = errorMetadata(err, "agreement_required")
        if (required && !none) return setNeeded(required.agreements)
        if (required)
          return client
            .declineOAuthAuthorization(id, "interaction_required")
            .then(({ redirect_to }) => leave.current(redirect_to), setFailure)
        setFailure(err)
      }
    )
  }, [request, needed, status, client, guard, id])

  const accept = (agreements: Agreement[]) => {
    setAccepting(true)
    setAcceptError(null)
    client
      .acceptAgreements(
        agreements.map(({ key, version }) => ({ key, version }))
      )
      .then(
        () => setNeeded(null),
        (err: unknown) => setAcceptError(err)
      )
      .finally(() => setAccepting(false))
  }

  const client_name = request?.client_name ?? ""
  let body: ReactNode
  if (needed && !failure) {
    body = (
      <AgreementsForm
        agreements={needed}
        busy={accepting}
        error={acceptError}
        onAccept={() => accept(needed)}
        onBack={() =>
          void client
            .declineOAuthAuthorization(id, "access_denied")
            .then(({ redirect_to }) => leave.current(redirect_to), setFailure)
        }
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
      </div>
    )
  } else if (
    request &&
    status === "signed_out" &&
    !request.prompt.includes("none")
  ) {
    return (
      <SignInPanel
        className={className}
        description={t("oauth.signInTo", { client: client_name })}
        {...signIn}
      />
    )
  } else {
    body = (
      <div
        role="status"
        className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground"
      >
        <Spinner />
        {request
          ? t("oauth.continuing", { client: client_name })
          : t("callback.completing")}
      </div>
    )
  }
  return (
    <AuthUiRoot className={className}>
      {layout(<div className="mx-auto w-full max-w-sm px-4 py-10">{body}</div>)}
    </AuthUiRoot>
  )
}
