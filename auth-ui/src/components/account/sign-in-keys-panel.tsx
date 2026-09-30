import {
  ComputerTerminal01Icon,
  FingerPrintIcon,
} from "@hugeicons/core-free-icons"
import { useId, useState } from "react"

import type { SignInKey } from "../../client/types.ts"
import { useMessages } from "../../i18n/context.ts"
import { useCapabilities } from "../../react/context.ts"
import { useSignInKeys } from "../../react/signInKeys.ts"
import { Badge } from "../../ui/badge.tsx"
import { Button } from "../../ui/button.tsx"
import { Field, FieldLabel } from "../../ui/field.tsx"
import { Input } from "../../ui/input.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { relativeTime } from "./lib.ts"
import { PanelRoot } from "./panel-root.tsx"
import { ConfirmDialog, ErrorNotice, PanelCard, SettingRow } from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface SignInKeysPanelProps {
  className?: string
}

/** Passkeys and device keys: add a passkey, rename or remove any key. */
export function SignInKeysPanel({ className }: SignInKeysPanelProps) {
  return (
    <PanelRoot className={className}>
      <SignInKeysCard />
    </PanelRoot>
  )
}

const webAuthn = () =>
  typeof window !== "undefined" && "PublicKeyCredential" in window

function SignInKeysCard() {
  const { t } = useMessages()
  const { capabilities } = useCapabilities()
  const keys = useSignInKeys({ guard: useStepUpGuard() })
  const [renaming, setRenaming] = useState<string | null>(null)
  const [removing, setRemoving] = useState<SignInKey | null>(null)
  const canAdd = !!capabilities?.passkeys.login && webAuthn()
  const list = keys.keys
  if (!canAdd && list?.length === 0) return null

  const name = (k: SignInKey) =>
    k.label ??
    (k.kind === "passkey"
      ? t("account.signInKeys.passkey")
      : t("account.signInKeys.deviceKey"))

  return (
    <PanelCard
      icon={FingerPrintIcon}
      title={t("account.signInKeys.title")}
      description={t("account.signInKeys.description")}
      action={
        canAdd && (
          <Button
            variant="outline"
            disabled={keys.busy}
            onClick={() => {
              setRenaming(null)
              void keys.addPasskey()
            }}
          >
            {keys.busy && !renaming && !removing && <Spinner />}
            {t("account.signInKeys.addPasskey")}
          </Button>
        )
      }
    >
      {!list && keys.loading && (
        <div className="flex justify-center px-6 py-6">
          <Spinner />
        </div>
      )}
      {list?.map((k) => (
        <SettingRow
          key={k.id}
          icon={k.kind === "passkey" ? FingerPrintIcon : ComputerTerminal01Icon}
          title={name(k)}
          badge={
            k.current ? (
              <Badge variant="secondary">
                {t("account.signInKeys.current")}
              </Badge>
            ) : null
          }
          description={[
            k.label
              ? k.kind === "passkey"
                ? t("account.signInKeys.passkey")
                : t("account.signInKeys.deviceKey")
              : null,
            t("account.signInKeys.added", { time: relativeTime(k.created_at) }),
            k.last_used_at
              ? t("account.signInKeys.lastUsed", {
                  time: relativeTime(k.last_used_at),
                })
              : null,
          ]
            .filter(Boolean)
            .join(" · ")}
          actions={
            renaming === k.id ? null : (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={keys.busy}
                  onClick={() => setRenaming(k.id)}
                >
                  {t("account.signInKeys.rename")}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={keys.busy}
                  aria-label={`${t("account.signInKeys.remove")}: ${name(k)}`}
                  onClick={() => setRemoving(k)}
                >
                  {t("account.signInKeys.remove")}
                </Button>
              </>
            )
          }
        >
          {renaming === k.id && (
            <RenameForm
              initial={k.label ?? ""}
              busy={keys.busy}
              onCancel={() => setRenaming(null)}
              onSubmit={async (label) => {
                await keys.rename(k.id, label)
                setRenaming(null)
              }}
            />
          )}
        </SettingRow>
      ))}
      {list?.length === 0 && (
        <p className="px-5 py-4 text-sm text-muted-foreground sm:px-6">
          {t("account.signInKeys.none")}
        </p>
      )}
      {keys.error && (
        <div className="px-5 py-4 sm:px-6">
          <ErrorNotice error={keys.error} />
        </div>
      )}
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={t("account.signInKeys.removeTitle", {
          name: removing ? name(removing) : "",
        })}
        description={t("account.signInKeys.removeDescription")}
        confirmLabel={t("account.signInKeys.remove")}
        destructive
        onConfirm={() => {
          const k = removing
          setRemoving(null)
          if (k) void keys.revoke(k.id)
        }}
      />
    </PanelCard>
  )
}

function RenameForm({
  initial,
  busy,
  onSubmit,
  onCancel,
}: {
  initial: string
  busy: boolean
  onSubmit: (label: string) => unknown
  onCancel: () => void
}) {
  const { t } = useMessages()
  const id = useId()
  const [label, setLabel] = useState(initial)
  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault()
        if (label.trim()) void onSubmit(label)
      }}
    >
      <Field>
        <FieldLabel htmlFor={id}>{t("account.signInKeys.label")}</FieldLabel>
        <Input
          id={id}
          autoFocus
          maxLength={100}
          value={label}
          disabled={busy}
          onChange={(e) => setLabel(e.target.value)}
          className="sm:max-w-sm"
        />
      </Field>
      <div className="flex flex-col gap-2 sm:flex-row">
        <Button type="submit" disabled={busy || !label.trim()}>
          {busy && <Spinner />}
          {busy ? t("common.saving") : t("common.save")}
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
