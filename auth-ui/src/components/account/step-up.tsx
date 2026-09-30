import { SecurityCheckIcon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useEffect, useId, useState, type ReactNode } from "react"

import { readStepUpReturn } from "../../client/client.ts"
import type { StepUpChallenge } from "../../client/continuation.ts"
import { useMessages } from "../../i18n/context.ts"
import type { MessageKey } from "../../i18n/messages.ts"
import { useAuthClient, useCapabilities } from "../../react/context.ts"
import { useStepUp, type StepUpController } from "../../react/useStepUp.ts"
import { Button } from "../../ui/button.tsx"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../ui/dialog.tsx"
import { Field, FieldLabel } from "../../ui/field.tsx"
import { Input } from "../../ui/input.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { Tabs, TabsList, TabsTrigger } from "../../ui/tabs.tsx"
import { CodeStep, ErrorNotice } from "./shared.tsx"
import { StepUpContext } from "./step-up-context.ts"

export interface StepUpProviderProps {
  children?: ReactNode
  /** Where OIDC step-up sends the browser. Default `location.assign`. */
  navigate?: (url: string) => void
  /** Where OIDC step-up returns. Default the current URL. */
  returnTo?: string
}

/**
 * One step-up dialog for a subtree: every account panel inside runs its
 * sensitive actions through this provider's `guard`.
 */
export function StepUpProvider({
  children,
  navigate,
  returnTo,
}: StepUpProviderProps) {
  const controller = useStepUp({ navigate })
  return (
    <StepUpContext.Provider value={controller}>
      {children}
      <StepUpDialog controller={controller} returnTo={returnTo} />
      <StepUpReturn />
    </StepUpContext.Provider>
  )
}

// Finishes an OIDC step-up redirect (?step_up=success|failed).
function StepUpReturn() {
  const client = useAuthClient()
  const { t } = useMessages()
  const [result] = useState(() =>
    typeof window === "undefined"
      ? null
      : readStepUpReturn(window.location.search)
  )
  const [dismissed, setDismissed] = useState(false)
  useEffect(() => {
    if (!result) return
    const url = new URL(window.location.href)
    url.searchParams.delete("step_up")
    window.history.replaceState(window.history.state, "", url)
    if (result === "success") void client.refresh()
  }, [client, result])
  return (
    <Dialog
      open={result === "failed" && !dismissed}
      onOpenChange={(open) => !open && setDismissed(true)}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("stepUp.title")}</DialogTitle>
          <DialogDescription>{t("stepUp.failed")}</DialogDescription>
        </DialogHeader>
        <DialogFooter showCloseButton />
      </DialogContent>
    </Dialog>
  )
}

export interface StepUpDialogProps {
  /** `useStepUp()`; `StepUpProvider` renders one for you. */
  controller: StepUpController
  returnTo?: string
}

const CODE_METHODS = ["totp", "email", "sms"] as const
type CodeMethod = (typeof CODE_METHODS)[number]
const isCodeMethod = (m: string): m is CodeMethod =>
  (CODE_METHODS as readonly string[]).includes(m)

function codeMethods(challenge: StepUpChallenge): CodeMethod[] {
  if (!challenge.methods.includes("2fa")) return []
  const tf = challenge.twoFactor
  const listed = [
    ...(tf?.options?.map((o) => o.method) ?? []),
    ...(tf?.methods ?? []),
  ].filter(isCodeMethod)
  const unique = [...new Set(listed)]
  const def = tf?.default_method
  if (def && isCodeMethod(def) && unique.includes(def))
    unique.sort((a, b) => (a === def ? -1 : b === def ? 1 : 0))
  return unique.length ? unique : ["totp"]
}

/** Re-authentication for a pending sensitive action; open while one waits. */
export function StepUpDialog({ controller, returnTo }: StepUpDialogProps) {
  const { t } = useMessages()
  const { state, busy } = controller
  const challenge = state.step === "idle" ? null : state.challenge
  // Keeps content during the close animation.
  const [shown, setShown] = useState(challenge)
  if (challenge && challenge !== shown) setShown(challenge)

  return (
    <Dialog
      open={!!challenge}
      onOpenChange={(open) => {
        if (!open && !busy) controller.cancel()
      }}
    >
      <DialogContent className="sm:max-w-[26rem]">
        <DialogHeader className="gap-3">
          <span
            aria-hidden
            className="flex size-10 items-center justify-center rounded-full bg-muted"
          >
            <HugeiconsIcon icon={SecurityCheckIcon} strokeWidth={1.75} />
          </span>
          <DialogTitle className="text-lg font-semibold">
            {t("stepUp.title")}
          </DialogTitle>
          <DialogDescription>{t("stepUp.description")}</DialogDescription>
        </DialogHeader>
        {shown && (
          <StepUpBody
            controller={controller}
            challenge={shown}
            returnTo={returnTo}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

const METHOD_LABEL: Record<CodeMethod, MessageKey> = {
  totp: "twoFactor.methods.totp",
  email: "twoFactor.methods.email",
  sms: "twoFactor.methods.sms",
}

function StepUpBody({
  controller,
  challenge,
  returnTo,
}: {
  controller: StepUpController
  challenge: StepUpChallenge
  returnTo?: string
}) {
  const { t } = useMessages()
  const { capabilities } = useCapabilities()
  const methods = codeMethods(challenge)
  const tabs: string[] = [
    ...(challenge.methods.includes("password") ? ["password"] : []),
    ...methods,
  ]
  const providers = challenge.methods.filter(
    (m) => m !== "password" && m !== "2fa"
  )
  const [tab, setTab] = useState(tabs[0] ?? "")
  const { busy } = controller

  const providerName = (id: string) =>
    capabilities?.external_login_providers.find((p) => p.id === id)?.name ??
    id.charAt(0).toUpperCase() + id.slice(1)

  return (
    <div className="grid gap-5">
      {tabs.length > 1 && (
        <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
          <TabsList className="w-full" aria-label={t("stepUp.chooseMethod")}>
            {tabs.map((m) => (
              <TabsTrigger key={m} value={m} disabled={busy}>
                {m === "password"
                  ? t("stepUp.methodPassword")
                  : t(METHOD_LABEL[m as CodeMethod])}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      )}
      {tab === "password" && <PasswordStepUp controller={controller} />}
      {isCodeMethod(tab) && (
        <CodeStepUp key={tab} controller={controller} method={tab} />
      )}
      {providers.length > 0 && (
        <div className="grid gap-2">
          {tabs.length > 0 && (
            <div className="flex items-center gap-3 text-xs text-muted-foreground uppercase">
              <span className="h-px flex-1 bg-border" />
              {t("common.or")}
              <span className="h-px flex-1 bg-border" />
            </div>
          )}
          {providers.map((p) => (
            <Button
              key={p}
              variant="outline"
              disabled={busy}
              title={t("stepUp.providerPrompt", { provider: providerName(p) })}
              onClick={() =>
                void controller.withProvider(
                  p,
                  returnTo ??
                    `${window.location.pathname}${window.location.search}${window.location.hash}`
                )
              }
            >
              {t("stepUp.withProvider", { provider: providerName(p) })}
            </Button>
          ))}
          {tabs.length === 0 && <ErrorNotice error={controller.error} />}
        </div>
      )}
      {tabs.length === 0 && providers.length === 0 && (
        <p className="text-sm text-muted-foreground">{t("stepUp.noMethods")}</p>
      )}
    </div>
  )
}

function PasswordStepUp({ controller }: { controller: StepUpController }) {
  const { t } = useMessages()
  const [password, setPassword] = useState("")
  const id = useId()
  const { busy } = controller
  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault()
        if (password) void controller.withPassword(password)
      }}
    >
      <Field>
        <FieldLabel htmlFor={id}>{t("fields.password")}</FieldLabel>
        <Input
          id={id}
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          disabled={busy}
          aria-invalid={!!controller.error || undefined}
          onChange={(e) => setPassword(e.target.value)}
        />
      </Field>
      <ErrorNotice error={controller.error} />
      <Button type="submit" disabled={busy || !password}>
        {busy && <Spinner />}
        {busy ? t("stepUp.confirming") : t("stepUp.submit")}
      </Button>
    </form>
  )
}

function CodeStepUp({
  controller,
  method,
}: {
  controller: StepUpController
  method: CodeMethod
}) {
  const { t } = useMessages()
  const [backup, setBackup] = useState(false)
  const [backupCode, setBackupCode] = useState("")
  const backupId = useId()
  const { state, busy, error } = controller
  const sent = state.step === "code_sent" && state.method === method

  const toggle = (
    <Button
      type="button"
      variant="link"
      className="h-auto justify-self-start p-0 text-muted-foreground"
      disabled={busy}
      onClick={() => setBackup((b) => !b)}
    >
      {backup ? t("stepUp.useCode") : t("stepUp.useBackup")}
    </Button>
  )

  if (backup)
    return (
      <form
        className="grid gap-4"
        onSubmit={(e) => {
          e.preventDefault()
          const code = backupCode.trim()
          if (code) void controller.withTwoFactor(code, { backupCode: true })
        }}
      >
        <Field>
          <FieldLabel htmlFor={backupId}>
            {t("twoFactor.backupCodes")}
          </FieldLabel>
          <Input
            id={backupId}
            autoComplete="one-time-code"
            autoFocus
            spellCheck={false}
            placeholder={t("twoFactor.backupPlaceholder")}
            className="font-mono"
            value={backupCode}
            disabled={busy}
            onChange={(e) => setBackupCode(e.target.value)}
          />
        </Field>
        <p className="-mt-2 text-sm text-muted-foreground">
          {t("stepUp.backupPrompt")}
        </p>
        <ErrorNotice error={error} />
        <Button type="submit" disabled={busy || !backupCode.trim()}>
          {busy && <Spinner />}
          {t("stepUp.submit")}
        </Button>
        {toggle}
      </form>
    )

  if (method !== "totp" && !sent)
    return (
      <div className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          {t("stepUp.sendPrompt", {
            method: t(METHOD_LABEL[method]).toLowerCase(),
          })}
        </p>
        <ErrorNotice error={error} />
        <Button
          disabled={busy}
          onClick={() => void controller.sendCode(method)}
        >
          {busy && <Spinner />}
          {busy ? t("common.sending") : t("common.sendCode")}
        </Button>
        {toggle}
      </div>
    )

  return (
    <div className="grid gap-3">
      <CodeStep
        key={sent ? state.verificationId : method}
        prompt={
          sent
            ? t("stepUp.codeSentTo", { destination: state.verificationId })
            : t("stepUp.totpPrompt")
        }
        busy={busy}
        error={error}
        submitLabel={t("stepUp.submit")}
        onSubmit={(code) => controller.withTwoFactor(code, { method })}
        onResend={sent ? () => controller.sendCode(method) : undefined}
      />
      {toggle}
    </div>
  )
}
