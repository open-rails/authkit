import { cn } from "cn"
import { useState, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import { AuthUiRoot } from "#authui/scope"
import { isEntryStep } from "./labels.ts"
import {
  SignInFlow,
  type SignInFlowProps,
  type SignInStep,
} from "./SignInFlow.tsx"

export type SignInSlots = {
  logo?: ReactNode
  title?: ReactNode
  description?: ReactNode
  // Between the title and the tabs, e.g. a promo line.
  header?: ReactNode
}

export type SignInPanelProps = SignInFlowProps &
  SignInSlots & {
    className?: string
  }

// Inline sign-in card, e.g. for a dedicated /login page.
export function SignInPanel({
  logo,
  title,
  description,
  header,
  className,
  ...flow
}: SignInPanelProps) {
  const { t } = useMessages()
  const [step, setStep] = useState<SignInStep>(flow.initialTab ?? "login")
  return (
    <AuthUiRoot className={cn("w-full max-w-md", className)}>
      <section className="flex flex-col gap-5 rounded-xl bg-card p-6 text-sm text-card-foreground shadow-sm ring-1 ring-foreground/10">
        <div className="flex flex-col gap-1.5">
          {logo && <div className="mb-2 flex">{logo}</div>}
          <h1 className="text-lg leading-tight font-semibold">
            {title ?? t("signIn.titleCombined")}
          </h1>
          {isEntryStep(step) && (
            <p className="text-sm text-muted-foreground">
              {description ?? t("signIn.description")}
            </p>
          )}
        </div>
        {header}
        <SignInFlow
          {...flow}
          onStepChange={(s) => {
            setStep(s)
            flow.onStepChange?.(s)
          }}
        />
      </section>
    </AuthUiRoot>
  )
}
