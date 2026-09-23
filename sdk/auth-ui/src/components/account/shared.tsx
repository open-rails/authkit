import {
  AlertCircleIcon,
  CheckmarkCircle02Icon,
  ViewIcon,
  ViewOffIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon, type IconSvgElement } from "@hugeicons/react"
import { cn } from "cn"
import { REGEXP_ONLY_DIGITS_AND_CHARS } from "input-otp"
import { useId, useState, type ReactNode } from "react"

import type { AuthKitError } from "../../client/errors.ts"
import { useMessages } from "../../i18n/context.ts"
import { Alert, AlertDescription } from "../../ui/alert.tsx"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../ui/alert-dialog.tsx"
import { Button } from "../../ui/button.tsx"
import { Input } from "../../ui/input.tsx"
import { Card, CardDescription, CardHeader, CardTitle } from "../../ui/card.tsx"
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from "../../ui/input-otp.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { useCodeBudget, useCooldown } from "../sign-in/cooldown.ts"
import { CODE_LENGTH } from "./lib.ts"

export function PanelCard({
  icon,
  title,
  badge,
  description,
  action,
  tone,
  children,
  className,
}: {
  icon: IconSvgElement
  title: ReactNode
  badge?: ReactNode
  description?: ReactNode
  action?: ReactNode
  tone?: "danger"
  children?: ReactNode
  className?: string
}) {
  return (
    <Card
      className={cn(
        "gap-0 py-0",
        tone === "danger" && "ring-destructive/30",
        className
      )}
    >
      <CardHeader className="flex flex-col gap-4 px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:gap-6 sm:px-6">
        <div className="flex min-w-0 items-start gap-3.5">
          <span
            aria-hidden
            className={cn(
              "flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-foreground",
              tone === "danger" && "bg-destructive/10 text-destructive"
            )}
          >
            <HugeiconsIcon
              icon={icon}
              strokeWidth={1.75}
              className="size-[18px]"
            />
          </span>
          <div className="grid min-w-0 gap-1">
            <CardTitle className="flex flex-wrap items-center gap-2 text-base leading-tight font-semibold">
              {title}
              {badge}
            </CardTitle>
            {description && (
              <CardDescription className="text-pretty">
                {description}
              </CardDescription>
            )}
          </div>
        </div>
        {action && (
          <div className="flex shrink-0 gap-2 max-sm:w-full max-sm:[&>*]:flex-1">
            {action}
          </div>
        )}
      </CardHeader>
      {children && <div className="divide-y border-t">{children}</div>}
    </Card>
  )
}

export function SettingRow({
  icon,
  title,
  description,
  badge,
  actions,
  children,
  className,
  ...props
}: {
  icon?: IconSvgElement
  title: ReactNode
  description?: ReactNode
  badge?: ReactNode
  actions?: ReactNode
  children?: ReactNode
  className?: string
} & Omit<React.ComponentProps<"div">, "title">) {
  return (
    <div className={cn("px-5 py-4 sm:px-6", className)} {...props}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
        <div className="flex min-w-0 items-start gap-3">
          {icon && (
            <HugeiconsIcon
              icon={icon}
              strokeWidth={1.75}
              aria-hidden
              className="mt-0.5 size-[18px] shrink-0 text-muted-foreground"
            />
          )}
          <div className="grid min-w-0 gap-0.5">
            <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
              {title}
              {badge}
            </div>
            {description && (
              <div className="text-sm break-words text-muted-foreground">
                {description}
              </div>
            )}
          </div>
        </div>
        {actions && (
          <div className="flex shrink-0 flex-wrap items-center gap-2 max-sm:[&>*]:flex-1">
            {actions}
          </div>
        )}
      </div>
      {children && <div className="mt-4 sm:pl-[30px]">{children}</div>}
    </div>
  )
}

export function Notice({
  tone = "error",
  children,
  action,
  className,
}: {
  tone?: "error" | "success" | "warning"
  children: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <Alert
      variant={tone === "error" ? "destructive" : "default"}
      aria-live="polite"
      className={cn(
        tone === "success" && "border-success/30 text-success",
        tone === "warning" && "border-destructive/30",
        className
      )}
    >
      <HugeiconsIcon
        icon={tone === "success" ? CheckmarkCircle02Icon : AlertCircleIcon}
        strokeWidth={2}
      />
      <AlertDescription
        className={cn(
          "text-current",
          tone === "warning" && "text-foreground",
          action && "grid gap-3"
        )}
      >
        <span>{children}</span>
        {action}
      </AlertDescription>
    </Alert>
  )
}

export function ErrorNotice({
  error,
  className,
}: {
  error: unknown
  className?: string
}) {
  const { error: message } = useMessages()
  if (!error) return null
  return (
    <Notice className={className} tone="error">
      {message(error)}
    </Notice>
  )
}

export function CodeInput({
  value,
  onChange,
  onComplete,
  disabled,
  invalid,
  label,
  autoFocus = true,
}: {
  value: string
  onChange: (value: string) => void
  onComplete?: (value: string) => void
  disabled?: boolean
  invalid?: boolean
  label: string
  autoFocus?: boolean
}) {
  const half = CODE_LENGTH / 2
  const slots = (from: number) =>
    Array.from({ length: half }, (_, i) => (
      <InputOTPSlot
        key={from + i}
        index={from + i}
        aria-invalid={invalid || undefined}
        className="size-10 text-base sm:size-9 sm:text-sm"
      />
    ))
  return (
    <InputOTP
      maxLength={CODE_LENGTH}
      pattern={REGEXP_ONLY_DIGITS_AND_CHARS}
      inputMode="numeric"
      autoComplete="one-time-code"
      autoFocus={autoFocus}
      value={value}
      onChange={onChange}
      onComplete={onComplete}
      disabled={disabled}
      aria-label={label}
      aria-invalid={invalid || undefined}
    >
      <InputOTPGroup>{slots(0)}</InputOTPGroup>
      <InputOTPSeparator />
      <InputOTPGroup>{slots(half)}</InputOTPGroup>
    </InputOTP>
  )
}

// Enter a one-time code. With onResend, a wrong code stays retryable and a
// spent email/SMS code makes sending a new one the primary action.
export function CodeStep({
  prompt,
  busy,
  error,
  submitLabel,
  onSubmit,
  onResend,
  onCancel,
}: {
  prompt: ReactNode
  busy: boolean
  error: AuthKitError | null
  submitLabel?: string
  onSubmit: (code: string) => unknown
  onResend?: () => unknown
  onCancel?: () => void
}) {
  const { t } = useMessages()
  const [code, setCode] = useState("")
  const { left: wait, start: startWait } = useCooldown(30, !!onResend)
  const promptId = useId()
  const budget = useCodeBudget(error)
  const burned = !!onResend && budget.spent

  const submit = (value: string) => {
    if (busy || value.length < CODE_LENGTH) return
    setCode("")
    void onSubmit(value)
  }
  const resend = async () => {
    setCode("")
    startWait()
    budget.renew()
    await onResend?.()
  }

  return (
    <form
      className="grid gap-4"
      aria-describedby={promptId}
      onSubmit={(e) => {
        e.preventDefault()
        submit(code)
      }}
    >
      <p id={promptId} className="text-sm text-muted-foreground">
        {prompt}
      </p>
      {burned ? (
        <Notice
          tone="warning"
          action={
            <Button
              type="button"
              className="w-fit"
              disabled={busy}
              onClick={() => void resend()}
            >
              {busy && <Spinner />}
              {t("account.contact.sendNewCode")}
            </Button>
          }
        >
          {t("account.contact.codeBurned")}
        </Notice>
      ) : (
        <>
          <CodeInput
            value={code}
            onChange={setCode}
            onComplete={submit}
            disabled={busy}
            invalid={!!error}
            label={t("fields.verificationCode")}
          />
          <ErrorNotice error={error} />
        </>
      )}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        {!burned && (
          <Button type="submit" disabled={busy || code.length < CODE_LENGTH}>
            {busy && <Spinner />}
            {submitLabel ?? t("common.verify")}
          </Button>
        )}
        {onResend && !burned && (
          <Button
            type="button"
            variant="ghost"
            disabled={busy || wait > 0}
            onClick={() => void resend()}
          >
            {wait > 0
              ? t("common.resendIn", { seconds: wait })
              : t("common.resendCode")}
          </Button>
        )}
        {onCancel && (
          <Button
            type="button"
            variant="ghost"
            disabled={busy}
            onClick={onCancel}
            className="sm:ml-auto"
          >
            {t("common.cancel")}
          </Button>
        )}
      </div>
    </form>
  )
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  busy,
  destructive,
  disabled,
  onConfirm,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description: ReactNode
  confirmLabel: ReactNode
  busy?: boolean
  destructive?: boolean
  disabled?: boolean
  onConfirm: () => void
  children?: ReactNode
}) {
  const { t } = useMessages()
  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (!busy) onOpenChange(next)
      }}
    >
      <AlertDialogContent>
        <form
          className="grid gap-6"
          onSubmit={(e) => {
            e.preventDefault()
            onConfirm()
          }}
        >
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            <AlertDialogDescription>{description}</AlertDialogDescription>
          </AlertDialogHeader>
          {children}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>
              {t("common.cancel")}
            </AlertDialogCancel>
            <Button
              type="submit"
              variant={destructive ? "destructive" : "default"}
              disabled={busy || disabled}
            >
              {busy && <Spinner />}
              {confirmLabel}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

export function StatusBadge({
  on,
  children,
}: {
  on: boolean
  children: ReactNode
}) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1.5 rounded-full px-2 text-xs font-medium",
        on ? "bg-success/10 text-success" : "bg-muted text-muted-foreground"
      )}
    >
      <span
        aria-hidden
        className={cn(
          "size-1.5 rounded-full",
          on ? "bg-success" : "bg-muted-foreground/60"
        )}
      />
      {children}
    </span>
  )
}

export function PasswordInput(
  props: Omit<React.ComponentProps<typeof Input>, "type">
) {
  const { t } = useMessages()
  const [visible, setVisible] = useState(false)
  return (
    <div className="relative">
      <Input
        {...props}
        type={visible ? "text" : "password"}
        className="pr-10"
      />
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="absolute top-1/2 right-0.5 -translate-y-1/2 text-muted-foreground"
        aria-label={
          visible ? t("common.hidePassword") : t("common.showPassword")
        }
        aria-pressed={visible}
        onClick={() => setVisible((v) => !v)}
      >
        <HugeiconsIcon
          icon={visible ? ViewOffIcon : ViewIcon}
          strokeWidth={2}
        />
      </Button>
    </div>
  )
}
