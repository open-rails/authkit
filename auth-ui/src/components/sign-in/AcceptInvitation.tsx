import {
  AlertCircleIcon,
  CheckmarkCircle02Icon,
  UserAdd01Icon,
} from "@hugeicons/core-free-icons"
import { cn } from "cn"
import { useRef, useState, type ReactNode } from "react"

import type { Membership } from "#authui/client/generated/wire"
import { useMessages } from "#authui/i18n/context"
import { useAuthClient } from "#authui/react/context"
import { useTask } from "#authui/react/task"
import { useAuth } from "#authui/react/useAuth"
import { AuthUiRoot } from "#authui/scope"
import { Spinner } from "#authui/ui/spinner"
import { FormAlert, StepHeader, SubmitButton } from "./parts.tsx"
import type { SignInFlowProps, SignInStep } from "./SignInFlow.tsx"
import { SignInPanel } from "./SignInPanel.tsx"

export type AcceptInvitationProps = Omit<
  SignInFlowProps,
  "inviteCode" | "initialTab"
> & {
  // From the invitation link: readInvitation(location.hash).
  invitation?: { code: string; registers: boolean } | null
  // The group and role joined; null when signing up with the invitation
  // accepted it.
  onAccepted?: (membership: Membership | null) => void
  className?: string
}

// A role in words: `root:admin` is "admin".
const roleName = (role: string) => role.slice(role.indexOf(":") + 1)

// The invitation landing page (Frontend.InvitePath). Signed out, it signs in,
// or signs up with an email invitation, which then holds its role; signed
// in, it accepts the invitation into the account.
export function AcceptInvitation({
  invitation,
  onAccepted,
  className,
  ...flow
}: AcceptInvitationProps) {
  const { t, error: describe } = useMessages()
  const client = useAuthClient()
  const { status } = useAuth()
  const { busy, error, run } = useTask()
  const [accepted, setAccepted] = useState<{
    membership: Membership | null
  } | null>(null)
  // The entry the visitor last used: a sign-up with an email invitation has
  // accepted it already.
  const entry = useRef<SignInStep | null>(null)
  const accept = (membership: Membership | null) => {
    setAccepted({ membership })
    onAccepted?.(membership)
  }
  // A visitor who arrives signed out stays in the sign-in flow until it
  // finishes: its session starts before its last steps (backup codes).
  const [phase, setPhase] = useState<"sign_in" | "accept" | null>(null)
  if (phase === null && status === "signed_out") setPhase("sign_in")
  const current =
    phase ??
    (status === "signed_in"
      ? "accept"
      : status === "signed_out"
        ? "sign_in"
        : null)

  const card = (children: ReactNode) => (
    <AuthUiRoot className={cn("w-full max-w-md", className)}>
      <section className="flex flex-col gap-5 rounded-xl bg-card p-6 text-sm text-card-foreground shadow-sm ring-1 ring-foreground/10">
        {children}
      </section>
    </AuthUiRoot>
  )

  if (!invitation)
    return card(
      <div role="alert">
        <StepHeader
          icon={AlertCircleIcon}
          title={t("invitation.title")}
          description={t("invitation.missingLink")}
        />
      </div>
    )
  if (accepted) {
    const role = accepted.membership?.role
    return card(
      <div role="status">
        <StepHeader
          icon={CheckmarkCircle02Icon}
          title={t("invitation.accepted")}
          description={
            role
              ? t("invitation.joinedAs", { role: roleName(role) })
              : undefined
          }
        />
      </div>
    )
  }
  if (current === null)
    return card(
      <div
        role="status"
        className="flex items-center justify-center gap-2 py-6 text-muted-foreground"
      >
        <Spinner />
        {t("common.loading")}
      </div>
    )
  if (current === "accept")
    return card(
      <form
        className="flex flex-col gap-5"
        onSubmit={(e) => {
          e.preventDefault()
          void run(async () =>
            accept(await client.redeemInvitation(invitation.code))
          )
        }}
      >
        <StepHeader
          icon={UserAdd01Icon}
          title={t("invitation.title")}
          description={t("invitation.acceptDescription")}
        />
        {error && <FormAlert>{describe(error)}</FormAlert>}
        <SubmitButton busy={busy}>{t("invitation.accept")}</SubmitButton>
      </form>
    )
  return (
    <SignInPanel
      {...flow}
      className={className}
      title={t("invitation.title")}
      description={
        invitation.registers
          ? t("invitation.signUpDescription")
          : t("invitation.signInDescription")
      }
      inviteCode={invitation.registers ? invitation.code : undefined}
      initialTab={invitation.registers ? "register" : "login"}
      onStepChange={(step) => {
        if (step === "login" || step === "register") entry.current = step
        if (step === "verify_registration") entry.current = "register"
        flow.onStepChange?.(step)
      }}
      onSignedIn={(result) => {
        if (invitation.registers && entry.current === "register") accept(null)
        else setPhase("accept")
        flow.onSignedIn?.(result)
      }}
    />
  )
}
