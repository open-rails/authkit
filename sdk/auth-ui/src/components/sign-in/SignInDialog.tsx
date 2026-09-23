import { cn } from "cn"
import { useRef, useState } from "react"

import { useMessages } from "#authui/i18n/context"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "#authui/ui/dialog"
import type { SignInMode } from "./host.ts"
import { SignInFlow, type SignInStep } from "./SignInFlow.tsx"
import { isEntryStep } from "./labels.ts"
import type { SignInPanelProps } from "./SignInPanel.tsx"

export type SignInDialogProps = Omit<SignInPanelProps, "initialTab"> & {
  open: boolean
  onOpenChange: (open: boolean) => void
  // Read each time the dialog opens.
  initialTab?: SignInMode
  // false while a host overlay (e.g. a wallet picker) sits above the dialog:
  // the page stays interactive and an outside click does not dismiss it.
  modal?: boolean
}

// Closes itself after sign-in (after backup codes are acknowledged); until
// then it cannot be dismissed on the backup-codes screen.
export function SignInDialog({
  open,
  onOpenChange,
  logo,
  title,
  description,
  header,
  className,
  onSignedIn,
  modal = true,
  ...flow
}: SignInDialogProps) {
  const { t } = useMessages()
  const [step, setStep] = useState<SignInStep>(flow.initialTab ?? "login")
  const popup = useRef<HTMLDivElement>(null)
  const blocking = open && step === "backup_codes"

  return (
    <Dialog
      open={open}
      modal={modal}
      disablePointerDismissal={blocking || !modal}
      onOpenChange={(next) => {
        if (!next && blocking) return
        onOpenChange(next)
      }}
    >
      <DialogContent
        ref={popup}
        showCloseButton={!blocking}
        initialFocus={() =>
          popup.current?.querySelector<HTMLElement>(
            "input:not([type=hidden]):not([hidden]):not(:disabled)"
          ) ?? true
        }
        className={cn(
          "max-h-[calc(100dvh-2rem)] gap-5 overflow-y-auto sm:max-w-md",
          className
        )}
      >
        <DialogHeader className="gap-1.5 pr-8 text-left">
          {logo && <div className="mb-2 flex">{logo}</div>}
          <DialogTitle className="text-lg leading-tight font-semibold">
            {title ?? t("signIn.titleCombined")}
          </DialogTitle>
          <DialogDescription className={cn(!isEntryStep(step) && "sr-only")}>
            {description ?? t("signIn.description")}
          </DialogDescription>
        </DialogHeader>
        {header}
        <SignInFlow
          {...flow}
          onSignedIn={(result) => {
            onSignedIn?.(result)
            onOpenChange(false)
          }}
          onStepChange={(s) => {
            setStep(s)
            flow.onStepChange?.(s)
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
