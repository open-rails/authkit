import {
  Key01Icon,
  Mail01Icon,
  QrCode01Icon,
  ShieldKeyIcon,
  SmartPhone01Icon,
} from "@hugeicons/core-free-icons"
import type { IconSvgElement } from "@hugeicons/react"
import { useId, useState } from "react"

import type {
  RemovedMfaRole,
  TwoFactorFactor,
  TwoFactorMethod,
} from "../../client/types.ts"
import { useMessages } from "../../i18n/context.ts"
import type { MessageKey } from "../../i18n/messages.ts"
import { useUser } from "../../react/context.ts"
import { useTwoFactorSettings } from "../../react/twoFactor.ts"
import { Badge } from "../../ui/badge.tsx"
import { Button } from "../../ui/button.tsx"
import { Field, FieldDescription, FieldLabel } from "../../ui/field.tsx"
import { Input } from "../../ui/input.tsx"
import { RadioGroup, RadioGroupItem } from "../../ui/radio-group.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { BackupCodes } from "../sign-in/BackupCodes.tsx"
import { TotpSetup } from "../sign-in/TotpSetup.tsx"
import { PanelRoot } from "./panel-root.tsx"
import {
  CodeStep,
  ConfirmDialog,
  ErrorNotice,
  Notice,
  PanelCard,
  SettingRow,
  StatusBadge,
} from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface TwoFactorPanelProps {
  className?: string
}

/**
 * 2FA status, TOTP/email/SMS factors, the default factor, disabling, and
 * backup codes.
 */
export function TwoFactorPanel({ className }: TwoFactorPanelProps) {
  return (
    <PanelRoot className={className}>
      <TwoFactorCard />
    </PanelRoot>
  )
}

const METHODS: TwoFactorMethod[] = ["totp", "email", "sms"]
const isMethod = (m: string): m is TwoFactorMethod =>
  (METHODS as string[]).includes(m)

const ICON: Record<TwoFactorMethod, IconSvgElement> = {
  totp: QrCode01Icon,
  email: Mail01Icon,
  sms: SmartPhone01Icon,
}
const LABEL: Record<TwoFactorMethod, MessageKey> = {
  totp: "twoFactor.methods.totp",
  email: "twoFactor.methods.email",
  sms: "twoFactor.methods.sms",
}
const HINT: Record<TwoFactorMethod, MessageKey> = {
  totp: "twoFactor.hints.totp",
  email: "twoFactor.hints.email",
  sms: "twoFactor.hints.sms",
}
const E164 = /^\+[1-9]\d{6,14}$/

type Confirm =
  | { kind: "disable" }
  | { kind: "remove"; factor: TwoFactorFactor & { method: TwoFactorMethod } }
  | { kind: "regenerate" }

function TwoFactorCard() {
  const { t } = useMessages()
  const { user } = useUser()
  const tf = useTwoFactorSettings({ guard: useStepUpGuard() })
  const [adding, setAdding] = useState(false)
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const [removed, setRemoved] = useState<RemovedMfaRole[]>([])
  const { status, enrollment } = tf
  const enabled = !!status?.enabled
  const factors = (status?.factors ?? []).filter(
    (f): f is TwoFactorFactor & { method: TwoFactorMethod } =>
      isMethod(f.method)
  )
  const allowed = METHODS.filter(
    (m) => !status?.allowed_methods || status.allowed_methods.includes(m)
  )
  const available = allowed.filter((m) => !factors.some((f) => f.method === m))
  const enrolling = enrollment.step !== "idle"
  const label = (m: TwoFactorMethod) => t(LABEL[m])

  const destination = (f: TwoFactorFactor) =>
    f.method === "sms"
      ? (f.phone_number ?? undefined)
      : f.method === "email"
        ? (user?.email ?? undefined)
        : undefined

  const onConfirm = async () => {
    const c = confirm
    setConfirm(null)
    if (!c) return
    if (c.kind === "regenerate") return tf.regenerateBackupCodes()
    const roles = await tf.disable(
      c.kind === "remove" ? { factorId: c.factor.id } : {}
    )
    if (roles) setRemoved(roles)
  }

  return (
    <PanelCard
      icon={ShieldKeyIcon}
      title={t("account.twoFactor.title")}
      description={t("account.twoFactor.description")}
      badge={
        status && (
          <StatusBadge on={enabled}>
            {enabled ? t("account.twoFactor.on") : t("account.twoFactor.off")}
          </StatusBadge>
        )
      }
    >
      {!status && tf.loading && (
        <div className="flex justify-center px-6 py-6">
          <Spinner />
        </div>
      )}

      {enrollment.step === "backup_codes" && (
        <div className="bg-muted/40 px-5 py-5 sm:px-6">
          <BackupCodes
            codes={enrollment.codes}
            description={t("twoFactor.backupCodesDescription")}
            onAcknowledge={tf.dismiss}
            className="mx-auto max-w-sm"
          />
        </div>
      )}

      {enrollment.step === "totp" && (
        <SettingRow
          icon={ICON.totp}
          title={t("account.twoFactor.add")}
          description={label("totp")}
        >
          <div className="grid gap-6">
            <div className="w-full max-w-sm">
              <TotpSetup
                secret={enrollment.secret}
                otpauthUri={enrollment.otpauthUri}
              />
            </div>
            <CodeStep
              prompt={t("account.twoFactor.confirmTotp")}
              busy={tf.busy}
              error={tf.error}
              submitLabel={t("account.twoFactor.activate")}
              onSubmit={(code) => tf.confirm(code)}
              onCancel={tf.dismiss}
            />
          </div>
        </SettingRow>
      )}

      {enrollment.step === "code_sent" && (
        <SettingRow
          icon={ICON[enrollment.method]}
          title={t("account.twoFactor.add")}
          description={label(enrollment.method)}
        >
          <CodeStep
            prompt={t("account.twoFactor.codeSentTo", {
              destination:
                enrollment.method === "sms"
                  ? (enrollment.phoneNumber ?? "")
                  : (user?.email ?? t("account.twoFactor.yourEmail")),
            })}
            busy={tf.busy}
            error={tf.error}
            submitLabel={t("account.twoFactor.activate")}
            onSubmit={(code) => tf.confirm(code)}
            onResend={() =>
              tf.start({
                method: enrollment.method,
                phoneNumber: enrollment.phoneNumber,
                makeDefault: enrollment.makeDefault,
              })
            }
            onCancel={tf.dismiss}
          />
        </SettingRow>
      )}

      {adding && !enrolling && (
        <SettingRow title={t("account.twoFactor.chooseMethod")}>
          <MethodPicker
            methods={available}
            busy={tf.busy}
            error={tf.error}
            onCancel={() => setAdding(false)}
            onStart={async (input) => {
              await tf.start(input)
              setAdding(false)
            }}
          />
        </SettingRow>
      )}

      {factors.map((f) => (
        <SettingRow
          key={f.id ?? f.method}
          icon={ICON[f.method]}
          title={label(f.method)}
          badge={
            f.is_default && factors.length > 1 ? (
              <Badge variant="secondary">
                {t("account.twoFactor.default")}
              </Badge>
            ) : null
          }
          description={destination(f)}
          actions={
            <>
              {!f.is_default && f.id && (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={tf.busy}
                  onClick={() =>
                    void tf.setDefault({ factorId: f.id!, method: f.method })
                  }
                >
                  {t("account.twoFactor.makeDefault")}
                </Button>
              )}
              <Button
                variant="outline"
                size="sm"
                disabled={tf.busy}
                aria-label={`${t("account.twoFactor.remove")} ${label(f.method)}`}
                onClick={() => setConfirm({ kind: "remove", factor: f })}
              >
                {t("account.twoFactor.remove")}
              </Button>
            </>
          }
        />
      ))}

      {enabled && (
        <SettingRow
          icon={Key01Icon}
          title={t("account.twoFactor.backupTitle")}
          description={
            status?.backup_codes_remaining !== undefined
              ? t("account.twoFactor.backupRemaining", {
                  count: status.backup_codes_remaining,
                })
              : undefined
          }
          actions={
            <Button
              variant="outline"
              size="sm"
              disabled={tf.busy}
              onClick={() => setConfirm({ kind: "regenerate" })}
            >
              {t("account.twoFactor.regenerate")}
            </Button>
          }
        />
      )}

      {(removed.length > 0 || (tf.error && !enrolling && !adding)) && (
        <div className="grid gap-3 px-5 py-4 sm:px-6">
          {removed.length > 0 && (
            <Notice tone="warning">
              {t("account.twoFactor.removedRoles", {
                roles: removed.map((r) => r.role).join(", "),
              })}
            </Notice>
          )}
          {!enrolling && !adding && <ErrorNotice error={tf.error} />}
        </div>
      )}

      {status && !enrolling && !adding && (
        <div className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:px-6">
          {available.length > 0 && (
            <Button
              variant={enabled ? "outline" : "default"}
              disabled={tf.busy}
              onClick={() => {
                tf.dismiss()
                setAdding(true)
              }}
            >
              {enabled
                ? t("account.twoFactor.add")
                : t("account.twoFactor.enable")}
            </Button>
          )}
          {enabled && (
            <Button
              variant="ghost"
              className="text-destructive hover:text-destructive sm:ml-auto"
              disabled={tf.busy}
              onClick={() => setConfirm({ kind: "disable" })}
            >
              {t("account.twoFactor.disable")}
            </Button>
          )}
        </div>
      )}

      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={
          confirm?.kind === "regenerate"
            ? t("account.twoFactor.regenerateTitle")
            : confirm?.kind === "remove"
              ? t("account.twoFactor.removeTitle", {
                  method: label(confirm.factor.method),
                })
              : t("account.twoFactor.disableTitle")
        }
        description={
          confirm?.kind === "regenerate"
            ? t("account.twoFactor.regenerateDescription")
            : confirm?.kind === "remove"
              ? t("account.twoFactor.removeDescription")
              : t("account.twoFactor.disableDescription")
        }
        confirmLabel={
          confirm?.kind === "regenerate"
            ? t("account.twoFactor.regenerate")
            : confirm?.kind === "remove"
              ? t("account.twoFactor.remove")
              : t("account.twoFactor.disable")
        }
        destructive={confirm?.kind !== "regenerate"}
        onConfirm={() => void onConfirm()}
      />
    </PanelCard>
  )
}

function MethodPicker({
  methods,
  busy,
  error,
  onStart,
  onCancel,
}: {
  methods: TwoFactorMethod[]
  busy: boolean
  error: unknown
  onStart: (input: { method: TwoFactorMethod; phoneNumber?: string }) => unknown
  onCancel: () => void
}) {
  const { t } = useMessages()
  const [method, setMethod] = useState<TwoFactorMethod>(methods[0] ?? "totp")
  const [phone, setPhone] = useState("")
  const [touched, setTouched] = useState(false)
  const phoneId = useId()
  const normalized = phone.replace(/[\s().-]/g, "")
  const phoneInvalid = method === "sms" && !E164.test(normalized)

  return (
    <form
      className="grid gap-5"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        setTouched(true)
        if (phoneInvalid) return
        void onStart({
          method,
          phoneNumber: method === "sms" ? normalized : undefined,
        })
      }}
    >
      <RadioGroup
        value={method}
        onValueChange={(v) => setMethod(v as TwoFactorMethod)}
        aria-label={t("account.twoFactor.chooseMethod")}
        className="gap-2"
      >
        {methods.map((m) => (
          <FieldLabel
            key={m}
            className="w-full rounded-lg border p-3.5 has-data-checked:border-primary/40 has-data-checked:bg-primary/5"
          >
            <div className="flex w-full items-start gap-3">
              <RadioGroupItem value={m} className="mt-0.5" disabled={busy} />
              <div className="grid gap-1">
                <span className="text-sm font-medium">{t(LABEL[m])}</span>
                <span className="text-sm font-normal text-muted-foreground">
                  {t(HINT[m])}
                </span>
              </div>
            </div>
          </FieldLabel>
        ))}
      </RadioGroup>
      {method === "sms" && (
        <Field data-invalid={(touched && phoneInvalid) || undefined}>
          <FieldLabel htmlFor={phoneId}>{t("fields.phone")}</FieldLabel>
          <Input
            id={phoneId}
            type="tel"
            inputMode="tel"
            autoComplete="tel"
            placeholder={t("fields.phonePlaceholder")}
            value={phone}
            disabled={busy}
            aria-invalid={(touched && phoneInvalid) || undefined}
            onChange={(e) => setPhone(e.target.value)}
            className="sm:max-w-xs"
          />
          <FieldDescription>
            {touched && phoneInvalid
              ? t("validation.phoneInvalid")
              : t("account.contact.phoneHint")}
          </FieldDescription>
        </Field>
      )}
      <ErrorNotice error={error} />
      <div className="flex flex-col gap-2 sm:flex-row">
        <Button type="submit" disabled={busy}>
          {busy && <Spinner />}
          {t("common.continue")}
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
