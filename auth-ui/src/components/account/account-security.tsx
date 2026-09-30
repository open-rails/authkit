import type { ReactNode } from "react"

import { AuthUiRoot } from "../../scope.tsx"
import { ContactPanel, type ContactChannel } from "./contact-panel.tsx"
import { DeleteAccountPanel } from "./delete-account-panel.tsx"
import { LinkedProvidersPanel } from "./linked-providers-panel.tsx"
import { PasswordPanel } from "./password-panel.tsx"
import { SessionsPanel } from "./sessions-panel.tsx"
import { StepUpProvider } from "./step-up.tsx"
import { useStepUpController } from "./step-up-context.ts"
import { TwoFactorPanel } from "./two-factor-panel.tsx"

export type AccountSecuritySection =
  "contact" | "password" | "providers" | "twoFactor" | "sessions" | "delete"

const ALL: AccountSecuritySection[] = [
  "contact",
  "password",
  "providers",
  "twoFactor",
  "sessions",
  "delete",
]

export interface AccountSecurityProps {
  /** Which panels to show, in order. Default all. */
  sections?: readonly AccountSecuritySection[]
  contactChannels?: readonly ContactChannel[]
  /** Extra linked-account rows, e.g. `<SolanaLinkRow>` from `./solana`. */
  linkedAccountRows?: ReactNode
  /** Browser navigation for provider linking and OIDC step-up. */
  navigate?: (url: string) => void
  /** Where OIDC step-up returns. Default the current URL. */
  stepUpReturnTo?: string
  /** Runs after account deletion; the session has already ended. */
  onDeleted?: () => void
  className?: string
}

/** Every account security panel, sharing one step-up dialog. */
export function AccountSecurity({
  sections = ALL,
  contactChannels,
  linkedAccountRows,
  navigate,
  stepUpReturnTo,
  onDeleted,
  className,
}: AccountSecurityProps) {
  const panels = sections.map((section) => {
    switch (section) {
      case "contact":
        return <ContactPanel key={section} channels={contactChannels} />
      case "password":
        return <PasswordPanel key={section} />
      case "providers":
        return (
          <LinkedProvidersPanel
            key={section}
            navigate={navigate}
            extraRows={linkedAccountRows}
          />
        )
      case "twoFactor":
        return <TwoFactorPanel key={section} />
      case "sessions":
        return <SessionsPanel key={section} />
      case "delete":
        return <DeleteAccountPanel key={section} onDeleted={onDeleted} />
    }
  })
  const root = (
    <AuthUiRoot className={["grid gap-6", className].filter(Boolean).join(" ")}>
      {panels}
    </AuthUiRoot>
  )
  return useStepUpController() ? (
    root
  ) : (
    <StepUpProvider navigate={navigate} returnTo={stepUpReturnTo}>
      {root}
    </StepUpProvider>
  )
}
