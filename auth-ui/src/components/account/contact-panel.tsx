import {
  Mail01Icon,
  SmartPhone01Icon,
  UserAccountIcon,
} from "@hugeicons/core-free-icons"
import { useId, useState } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useUser } from "../../react/context.ts"
import { useContactVerification } from "../../react/providers.ts"
import { Badge } from "../../ui/badge.tsx"
import { Button } from "../../ui/button.tsx"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "../../ui/field.tsx"
import { Input } from "../../ui/input.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { PanelRoot } from "./panel-root.tsx"
import {
  CodeStep,
  ErrorNotice,
  Notice,
  PanelCard,
  SettingRow,
} from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export type ContactChannel = "email" | "phone"

export interface ContactPanelProps {
  /** Which contacts to manage. Default both. */
  channels?: readonly ContactChannel[]
  className?: string
}

/** Change or verify email and phone with a one-time code. */
export function ContactPanel({
  channels = ["email", "phone"],
  className,
}: ContactPanelProps) {
  return (
    <PanelRoot className={className}>
      <ContactCard channels={channels} />
    </PanelRoot>
  )
}

function ContactCard({ channels }: { channels: readonly ContactChannel[] }) {
  const { t } = useMessages()
  return (
    <PanelCard
      icon={UserAccountIcon}
      title={t("account.contact.title")}
      description={t("account.contact.description")}
    >
      {channels.map((c) => (
        <ContactRow key={c} channel={c} />
      ))}
    </PanelCard>
  )
}

const E164 = /^\+[1-9]\d{6,14}$/
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const normalizePhone = (v: string) => v.replace(/[\s().-]/g, "")

function ContactRow({ channel }: { channel: ContactChannel }) {
  const { t } = useMessages()
  const { user } = useUser()
  const flow = useContactVerification({ guard: useStepUpGuard() })
  const [editing, setEditing] = useState(false)
  const email = channel === "email"
  const value = (email ? user?.email : user?.phone_number) ?? ""
  const verified = email ? !!user?.email_verified : !!user?.phone_verified
  const { state } = flow

  const close = () => {
    flow.reset()
    setEditing(false)
  }
  const active = editing || state.step !== "idle"

  return (
    <SettingRow
      icon={email ? Mail01Icon : SmartPhone01Icon}
      title={email ? t("account.email.title") : t("account.phone.title")}
      badge={
        value ? (
          <Badge variant={verified ? "secondary" : "destructive"}>
            {verified ? t("common.verified") : t("common.unverified")}
          </Badge>
        ) : null
      }
      description={
        value ? (
          <span className="font-medium text-foreground/80">{value}</span>
        ) : (
          t("account.contact.noneSet")
        )
      }
      actions={
        !active && user ? (
          <>
            {value && !verified && (
              <Button
                variant="outline"
                size="sm"
                disabled={flow.busy}
                onClick={() => void flow.request(value)}
              >
                {flow.busy && <Spinner />}
                {t("account.contact.verify")}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                flow.reset()
                setEditing(true)
              }}
            >
              {value ? t("account.contact.change") : t("account.contact.add")}
            </Button>
          </>
        ) : null
      }
    >
      {state.step === "code_sent" ? (
        <CodeStep
          prompt={t("account.contact.codeSentTo", { value: state.identifier })}
          busy={flow.busy}
          error={flow.error}
          submitLabel={
            email ? t("account.email.confirmChange") : t("account.phone.verify")
          }
          onSubmit={(code) => flow.confirm(code)}
          onResend={() => flow.resend()}
          onCancel={close}
        />
      ) : state.step === "done" ? (
        <Notice
          tone="success"
          action={
            <Button
              variant="outline"
              size="sm"
              className="w-fit"
              onClick={close}
            >
              {t("common.close")}
            </Button>
          }
        >
          {email ? t("account.email.changed") : t("account.phone.verified")}
        </Notice>
      ) : editing ? (
        <ContactForm
          channel={channel}
          current={value}
          busy={flow.busy}
          error={flow.error}
          onSubmit={(next) => flow.request(next)}
          onCancel={close}
        />
      ) : flow.error ? (
        <ErrorNotice error={flow.error} />
      ) : null}
    </SettingRow>
  )
}

function ContactForm({
  channel,
  current,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  channel: ContactChannel
  current: string
  busy: boolean
  error: unknown
  onSubmit: (value: string) => unknown
  onCancel: () => void
}) {
  const { t } = useMessages()
  const id = useId()
  const [value, setValue] = useState("")
  const [touched, setTouched] = useState(false)
  const email = channel === "email"
  const next = email ? value.trim() : normalizePhone(value)

  const invalid = email
    ? !EMAIL.test(next)
      ? t("validation.emailInvalid")
      : next.toLowerCase() === current.toLowerCase()
        ? t("account.email.unchanged")
        : null
    : !E164.test(next)
      ? t("validation.phoneInvalid")
      : next === current
        ? t("account.phone.unchanged")
        : null
  const shown = touched ? invalid : null

  return (
    <form
      className="grid gap-4"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        setTouched(true)
        if (!invalid) void onSubmit(next)
      }}
    >
      <Field data-invalid={!!shown || undefined}>
        <FieldLabel htmlFor={id}>
          {email ? t("account.email.newEmail") : t("fields.phone")}
        </FieldLabel>
        <Input
          id={id}
          type={email ? "email" : "tel"}
          inputMode={email ? "email" : "tel"}
          autoComplete={email ? "email" : "tel"}
          autoFocus
          placeholder={
            email ? t("fields.emailPlaceholder") : t("fields.phonePlaceholder")
          }
          value={value}
          disabled={busy}
          aria-invalid={!!shown || undefined}
          onChange={(e) => setValue(e.target.value)}
          className="sm:max-w-sm"
        />
        {shown ? (
          <FieldError>{shown}</FieldError>
        ) : (
          <FieldDescription>
            {email
              ? t("account.email.changeDescription")
              : t("account.contact.phoneHint")}
          </FieldDescription>
        )}
      </Field>
      <ErrorNotice error={error} />
      <div className="flex flex-col gap-2 sm:flex-row">
        <Button type="submit" disabled={busy}>
          {busy && <Spinner />}
          {busy ? t("common.sending") : t("common.sendCode")}
        </Button>
        <Button
          type="button"
          variant="ghost"
          disabled={busy}
          onClick={onCancel}
        >
          {t("common.cancel")}
        </Button>
      </div>
    </form>
  )
}
