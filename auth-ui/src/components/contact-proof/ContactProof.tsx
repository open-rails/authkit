import { cn } from "cn"
import { useEffect, useRef, useState, type ReactNode } from "react"

import type { ContactProofRequest } from "../../client/client.ts"
import { useMessages } from "../../i18n/context.ts"
import { useAuthClient } from "../../react/context.ts"
import { useContactVerification } from "../../react/providers.ts"
import { Button } from "../../ui/button.tsx"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "../../ui/dialog.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { CodeStep, ErrorNotice } from "../account/shared.tsx"

export interface VerifyContactFormProps {
  identifier: string
  onVerified: () => void
  onCancel?: () => void
}

/** Sends a code to the address and confirms it. */
export function VerifyContactForm({
  identifier,
  onVerified,
  onCancel,
}: VerifyContactFormProps) {
  const { t } = useMessages()
  const flow = useContactVerification()
  const verified = useRef(onVerified)
  useEffect(() => {
    verified.current = onVerified
  })
  useEffect(() => {
    if (flow.state.step === "done") verified.current()
  }, [flow.state.step])

  if (flow.state.step === "code_sent")
    return (
      <CodeStep
        prompt={t("account.contact.codeSentTo", { value: identifier })}
        busy={flow.busy}
        error={flow.error}
        submitLabel={t("common.verify")}
        onSubmit={(code) => flow.confirm(code)}
        onResend={() => flow.resend()}
        onCancel={onCancel}
      />
    )
  return (
    <div className="grid gap-4">
      <ErrorNotice error={flow.error} />
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={flow.busy}
          onClick={() => void flow.request(identifier)}
        >
          {flow.busy && <Spinner />}
          {t("common.sendCode")}
        </Button>
        {onCancel && (
          <Button
            type="button"
            variant="ghost"
            disabled={flow.busy}
            onClick={onCancel}
          >
            {t("common.cancel")}
          </Button>
        )}
      </div>
    </div>
  )
}

export interface ContactProofDialogProps {
  title?: ReactNode
  description?: ReactNode
  className?: string
}

type Pending = {
  request: ContactProofRequest
  resolve: (proven: boolean) => void
}

/**
 * Answers AuthKit's contact_unproven refusals (403 verification_required):
 * while mounted it is the client's contact-proof handler, asks the user to
 * prove the address, and the refused request is retried once. Mount one
 * inside <AuthProvider>, or register your own handler with
 * client.onContactProofRequired.
 */
export function ContactProofDialog({
  title,
  description,
  className,
}: ContactProofDialogProps) {
  const { t } = useMessages()
  const client = useAuthClient()
  const [pending, setPending] = useState<Pending | null>(null)
  useEffect(
    () =>
      client.onContactProofRequired(
        (request) =>
          new Promise<boolean>((resolve) =>
            setPending((current) => {
              current?.resolve(false)
              return { request, resolve }
            })
          )
      ),
    [client]
  )
  const finish = (proven: boolean) => {
    pending?.resolve(proven)
    setPending(null)
  }
  const phone = pending?.request.channel === "phone"
  return (
    <Dialog
      open={!!pending}
      onOpenChange={(open) => {
        if (!open) finish(false)
      }}
    >
      <DialogContent className={cn("gap-5 sm:max-w-md", className)}>
        <DialogHeader className="gap-1.5 pr-8 text-left">
          <DialogTitle className="text-lg leading-tight font-semibold">
            {title ??
              (phone
                ? t("contactProof.titlePhone")
                : t("contactProof.titleEmail"))}
          </DialogTitle>
          <DialogDescription>
            {description ??
              t("contactProof.description", {
                value: pending?.request.identifier ?? "",
              })}
          </DialogDescription>
        </DialogHeader>
        {pending && (
          <VerifyContactForm
            key={pending.request.identifier}
            identifier={pending.request.identifier}
            onVerified={() => finish(true)}
            onCancel={() => finish(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}
