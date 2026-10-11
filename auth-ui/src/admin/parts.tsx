import { Copy01Icon, Tick02Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { cn } from "cn"
import { useId, useState, type ComponentProps, type ReactNode } from "react"

import { ConfirmDialog, Notice } from "../components/account/shared.tsx"
import { Button } from "../ui/button.tsx"
import { Card, CardDescription, CardHeader, CardTitle } from "../ui/card.tsx"
import { Input } from "../ui/input.tsx"
import { Label } from "../ui/label.tsx"
import { Spinner } from "../ui/spinner.tsx"
import { useAdmin } from "./context.ts"
import { useAdminMessages } from "./i18n.ts"
import { Link } from "./link.tsx"

export function Section({
  title,
  description,
  actions,
  children,
  className,
  ...props
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children?: ReactNode
} & Omit<ComponentProps<"div">, "title">) {
  const id = useId()
  return (
    <Card
      role="region"
      aria-labelledby={id}
      className={cn("gap-0 py-0", className)}
      {...props}
    >
      <CardHeader className="flex flex-col gap-3 px-5 py-5 sm:flex-row sm:items-start sm:justify-between sm:px-6">
        <div className="grid min-w-0 gap-1">
          <CardTitle className="text-base leading-tight font-semibold">
            <h2 id={id}>{title}</h2>
          </CardTitle>
          {description && (
            <CardDescription className="text-pretty">
              {description}
            </CardDescription>
          )}
        </div>
        {actions && (
          <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>
        )}
      </CardHeader>
      {children && <div className="border-t">{children}</div>}
    </Card>
  )
}

export function Body({ className, ...props }: ComponentProps<"div">) {
  return (
    <div className={cn("grid gap-4 px-5 py-4 sm:px-6", className)} {...props} />
  )
}

export function NoAccess() {
  const { t } = useAdminMessages()
  return (
    <Section title={t("common.noAccessTitle")} data-state="no-access">
      <Body>
        <p className="text-sm text-muted-foreground">{t("common.noAccess")}</p>
      </Body>
    </Section>
  )
}

export function Loading({ rows = 3 }: { rows?: number }) {
  const { t } = useAdminMessages()
  return (
    <div
      role="status"
      aria-label={t("common.loading")}
      className="grid gap-2 px-5 py-4 sm:px-6"
    >
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-9 animate-pulse rounded-md bg-muted" />
      ))}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="px-5 py-6 text-sm text-muted-foreground sm:px-6">
      {children}
    </p>
  )
}

// An AuthKit error as words; without a guard a step-up is "sign in again".
export function ErrorText({
  error,
  onRetry,
  className,
}: {
  error: unknown
  onRetry?: () => void
  className?: string
}) {
  const { t, error: message } = useAdminMessages()
  const { guard } = useAdmin()
  if (!error) return null
  const code = (error as { code?: string }).code
  return (
    <Notice
      className={className}
      tone="error"
      action={
        onRetry && (
          <Button
            variant="outline"
            size="sm"
            className="justify-self-start"
            onClick={onRetry}
          >
            {t("common.retry")}
          </Button>
        )
      }
    >
      {code === "step_up_required" && !guard
        ? t("common.signInAgain")
        : message(error)}
    </Notice>
  )
}

export function Table({ className, ...props }: ComponentProps<"table">) {
  return (
    <div className="overflow-x-auto">
      <table className={cn("w-full text-sm", className)} {...props} />
    </div>
  )
}

export function Th({ className, ...props }: ComponentProps<"th">) {
  return (
    <th
      scope="col"
      className={cn(
        "px-5 py-2.5 text-left text-xs font-medium whitespace-nowrap text-muted-foreground first:pl-5 sm:px-6",
        className
      )}
      {...props}
    />
  )
}

export function Td({ className, ...props }: ComponentProps<"td">) {
  return (
    <td
      className={cn("border-t px-5 py-3 align-middle sm:px-6", className)}
      {...props}
    />
  )
}

export function Select({ className, ...props }: ComponentProps<"select">) {
  return (
    <select
      className={cn(
        "h-9 min-w-0 rounded-md border border-input bg-transparent px-2 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30",
        className
      )}
      {...props}
    />
  )
}

export function FormField({
  label,
  hint,
  children,
  htmlFor,
}: {
  label: ReactNode
  hint?: ReactNode
  htmlFor: string
  children: ReactNode
}) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

// A secret shown once: read-only, selected on focus, with a copy button.
export function SecretField({
  label,
  value,
}: {
  label: string
  value: string
}) {
  const { t } = useAdminMessages()
  const id = useId()
  const [copied, setCopied] = useState(false)
  return (
    <div role="status" className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2">
        <Input
          id={id}
          readOnly
          value={value}
          className="font-mono text-xs"
          onFocus={(e) => e.target.select()}
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          aria-label={copied ? t("common.copied") : t("common.copy")}
          onClick={() =>
            void navigator.clipboard?.writeText(value).then(
              () => setCopied(true),
              () => undefined
            )
          }
        >
          <HugeiconsIcon
            icon={copied ? Tick02Icon : Copy01Icon}
            strokeWidth={2}
          />
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{t("common.secretOnce")}</p>
    </div>
  )
}

// A destructive act confirmed by typing word.
export function TypedConfirm({
  open,
  onOpenChange,
  title,
  description,
  word,
  confirmLabel,
  busy,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description: ReactNode
  word: string
  confirmLabel: ReactNode
  busy?: boolean
  onConfirm: () => void
}) {
  const { t } = useAdminMessages()
  const id = useId()
  const [typed, setTyped] = useState("")
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setTyped("")
        onOpenChange(next)
      }}
      title={title}
      description={description}
      confirmLabel={confirmLabel}
      busy={busy}
      destructive
      disabled={typed.trim() !== word}
      onConfirm={onConfirm}
    >
      <div className="grid gap-1.5">
        <Label htmlFor={id}>{t("common.typeToConfirm", { word })}</Label>
        <Input
          id={id}
          autoComplete="off"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
        />
      </div>
    </ConfirmDialog>
  )
}

export { ConfirmDialog }

export function ViewTabs({
  items,
  label,
}: {
  items: { to: string; label: ReactNode; current: boolean }[]
  label: string
}) {
  return (
    <nav aria-label={label} className="flex gap-1 border-b">
      {items.map((item) => (
        <Link
          key={item.to}
          to={item.to}
          aria-current={item.current ? "page" : undefined}
          className={cn(
            "-mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground",
            item.current && "border-primary text-foreground"
          )}
        >
          {item.label}
        </Link>
      ))}
    </nav>
  )
}

export function LoadMore({
  onClick,
  busy,
  count,
}: {
  onClick?: () => void
  busy?: boolean
  count: number
}) {
  const { t } = useAdminMessages()
  return (
    <div className="flex items-center justify-between gap-3 border-t px-5 py-3 sm:px-6">
      <p aria-live="polite" className="text-xs text-muted-foreground">
        {t("common.showing", { count })}
      </p>
      {onClick && (
        <Button variant="outline" size="sm" disabled={busy} onClick={onClick}>
          {busy && <Spinner />}
          {t("common.loadMore")}
        </Button>
      )}
    </div>
  )
}
