import {
  AlertCircleIcon,
  Copy01Icon,
  Tick02Icon,
  CheckmarkCircle02Icon,
  ViewIcon,
  ViewOffIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon, type IconSvgElement } from "@hugeicons/react"
import { cn } from "cn"
import { REGEXP_ONLY_DIGITS } from "input-otp"
import { useId, useState, type ComponentProps, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import { Alert, AlertDescription } from "#authui/ui/alert"
import { Button } from "#authui/ui/button"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "#authui/ui/input-group"
import { InputOTP, InputOTPGroup, InputOTPSlot } from "#authui/ui/input-otp"
import { Label } from "#authui/ui/label"
import { Separator } from "#authui/ui/separator"
import { Spinner } from "#authui/ui/spinner"

export function StepHeader({
  icon,
  title,
  description,
}: {
  icon?: IconSvgElement
  title: ReactNode
  description?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-2 text-center">
      {icon && (
        <span className="flex size-11 items-center justify-center rounded-full bg-primary/10 text-primary">
          <HugeiconsIcon icon={icon} className="size-5" strokeWidth={2} />
        </span>
      )}
      <h2 className="text-lg leading-tight font-semibold">{title}</h2>
      {description && (
        <p className="text-sm text-balance text-muted-foreground">
          {description}
        </p>
      )}
    </div>
  )
}

export function FormAlert({
  children,
  action,
  tone = "error",
  className,
}: {
  children: ReactNode
  action?: ReactNode
  tone?: "error" | "success"
  className?: string
}) {
  return (
    <Alert
      variant={tone === "error" ? "destructive" : "default"}
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        tone === "error"
          ? "border-destructive/30 bg-destructive/5"
          : "border-success/30 bg-success/5 text-success",
        className
      )}
    >
      <HugeiconsIcon
        icon={tone === "error" ? AlertCircleIcon : CheckmarkCircle02Icon}
        strokeWidth={2}
      />
      <AlertDescription
        className={cn(
          "flex flex-col items-start gap-2",
          tone === "error" ? "text-destructive" : "text-success"
        )}
      >
        <span>{children}</span>
        {action}
      </AlertDescription>
    </Alert>
  )
}

type TextFieldProps = Omit<ComponentProps<"input">, "id"> & {
  label: ReactNode
  icon?: IconSvgElement
  error?: ReactNode
  hint?: ReactNode
  // Rendered inside the field, after the input.
  trailing?: ReactNode
  id?: string
}

export function TextField({
  label,
  icon,
  error,
  hint,
  trailing,
  id,
  className,
  ...input
}: TextFieldProps) {
  const auto = useId()
  const fieldId = id ?? auto
  const messageId = `${fieldId}-message`
  const message = error || hint
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={fieldId}>{label}</Label>
      <InputGroup className="h-10">
        {icon && (
          <InputGroupAddon>
            <HugeiconsIcon icon={icon} strokeWidth={2} />
          </InputGroupAddon>
        )}
        <InputGroupInput
          id={fieldId}
          aria-invalid={error ? true : undefined}
          aria-describedby={message ? messageId : undefined}
          {...input}
        />
        {trailing && (
          <InputGroupAddon align="inline-end">{trailing}</InputGroupAddon>
        )}
      </InputGroup>
      {message && (
        <p
          id={messageId}
          role={error ? "alert" : undefined}
          className={cn(
            "text-xs",
            error ? "text-destructive" : "text-muted-foreground"
          )}
        >
          {message}
        </p>
      )}
    </div>
  )
}

export function PasswordField({
  extra,
  revealed,
  onRevealedChange,
  ...props
}: Omit<TextFieldProps, "type" | "trailing"> & {
  extra?: ReactNode
  revealed?: boolean
  onRevealedChange?: (revealed: boolean) => void
}) {
  const { t } = useMessages()
  const [own, setOwn] = useState(false)
  const visible = revealed ?? own
  const setVisible = (next: (v: boolean) => boolean) => {
    setOwn(next)
    onRevealedChange?.(next(visible))
  }
  const label = visible ? t("common.hidePassword") : t("common.showPassword")
  return (
    <TextField
      {...props}
      type={visible ? "text" : "password"}
      trailing={
        <>
          {extra}
          <InputGroupButton
            size="icon-xs"
            // Kept out of the tab order: tab moves field to field.
            tabIndex={-1}
            aria-label={label}
            title={label}
            aria-pressed={visible}
            onClick={() => setVisible((v) => !v)}
          >
            <HugeiconsIcon icon={visible ? ViewOffIcon : ViewIcon} />
          </InputGroupButton>
        </>
      }
    />
  )
}

export function CodeField({
  value,
  onChange,
  onComplete,
  label,
  invalid,
  disabled,
  autoFocus = true,
  length = 6,
}: {
  value: string
  onChange: (value: string) => void
  onComplete?: (value: string) => void
  label: string
  invalid?: boolean
  disabled?: boolean
  autoFocus?: boolean
  length?: number
}) {
  return (
    <InputOTP
      maxLength={length}
      pattern={REGEXP_ONLY_DIGITS}
      value={value}
      onChange={onChange}
      onComplete={onComplete}
      disabled={disabled}
      autoFocus={autoFocus}
      autoComplete="one-time-code"
      inputMode="numeric"
      name="code"
      aria-label={label}
      aria-invalid={invalid || undefined}
      containerClassName="justify-center"
    >
      <InputOTPGroup className="gap-1.5 sm:gap-2">
        {Array.from({ length }, (_, i) => (
          <InputOTPSlot
            key={i}
            index={i}
            className={cn(
              "size-11 rounded-md border text-lg font-medium first:rounded-md last:rounded-md sm:size-12",
              invalid && "border-destructive/60"
            )}
          />
        ))}
      </InputOTPGroup>
    </InputOTP>
  )
}

export function SubmitButton({
  busy,
  disabled,
  children,
  className,
  ...props
}: ComponentProps<typeof Button> & { busy?: boolean }) {
  return (
    <Button
      type="submit"
      size="lg"
      {...props}
      className={cn("w-full", className)}
      disabled={busy || disabled}
      aria-busy={busy || undefined}
    >
      {busy && <Spinner />}
      {children}
    </Button>
  )
}

export function TextButton({
  className,
  ...props
}: ComponentProps<typeof Button>) {
  return (
    <Button
      type="button"
      variant="link"
      size="sm"
      className={cn("h-auto p-0 font-medium", className)}
      {...props}
    />
  )
}

export function OrSeparator({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3" aria-hidden="true">
      <Separator className="flex-1" />
      <span className="text-xs text-muted-foreground uppercase">{label}</span>
      <Separator className="flex-1" />
    </div>
  )
}

export function CopyButton({
  text,
  label,
  className,
  ...props
}: Omit<ComponentProps<typeof Button>, "onClick" | "children"> & {
  text: string
  label?: string
}) {
  const { t } = useMessages()
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="outline"
      className={className}
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        })
      }}
      {...props}
    >
      <HugeiconsIcon icon={copied ? Tick02Icon : Copy01Icon} strokeWidth={2} />
      <span aria-live="polite">
        {copied ? t("common.copied") : (label ?? t("common.copy"))}
      </span>
    </Button>
  )
}
