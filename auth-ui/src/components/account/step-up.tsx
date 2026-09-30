import {
  FingerPrintIcon,
  SecurityCheckIcon,
  Wallet01Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useId, useState, type ReactNode } from "react"

import type { StepUpChallenge } from "../../client/stepUp.ts"
import type { TwoFactorFactor } from "../../client/types.ts"
import { webAuthnAvailable } from "../../client/webauthn.ts"
import { useMessages } from "../../i18n/context.ts"
import type { MessageKey } from "../../i18n/messages.ts"
import { useCapabilities, useUser } from "../../react/context.ts"
import { useStepUpReturn } from "../../react/providers.ts"
import {
  useStepUp,
  type StepUpChannel,
  type StepUpController,
} from "../../react/useStepUp.ts"
import type { SolanaSigner } from "../../solana/core.ts"
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
  /**
   * Resolves the linked Solana wallet's signer (e.g. once wallet-adapter
   * connects), for a wallet step-up. Without it the dialog offers no wallet.
   */
  acquireSolanaSigner?: () => Promise<SolanaSigner>
}

/**
 * One step-up dialog for a subtree: every account panel inside runs its
 * sensitive actions through this provider's `guard`.
 */
export function StepUpProvider({
  children,
  navigate,
  returnTo,
  acquireSolanaSigner,
}: StepUpProviderProps) {
  const controller = useStepUp({ navigate })
  return (
    <StepUpContext.Provider value={controller}>
      {children}
      <StepUpDialog
        controller={controller}
        returnTo={returnTo}
        acquireSolanaSigner={acquireSolanaSigner}
      />
      <StepUpReturn />
    </StepUpContext.Provider>
  )
}

// Finishes an OIDC step-up redirect (#code= or #error= on its return page).
function StepUpReturn() {
  const { t } = useMessages()
  const { error } = useStepUpReturn()
  const [dismissed, setDismissed] = useState(false)
  return (
    <Dialog
      open={!!error && !dismissed}
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
  acquireSolanaSigner?: () => Promise<SolanaSigner>
}

const CHANNELS: readonly string[] = ["email", "sms"]
const isChannel = (m: string): m is StepUpChannel => CHANNELS.includes(m)
// The step-up methods this dialog runs itself; any other is a provider.
const OWN_METHODS = new Set([
  "password",
  "2fa",
  "passkey",
  "solana",
  ...CHANNELS,
])

// The second factors a "2fa" step-up can use, the default first.
function codeFactors(challenge: StepUpChallenge): TwoFactorFactor[] {
  if (!challenge.methods.includes("2fa")) return []
  return [...challenge.factors].sort(
    (a, b) => Number(b.is_default) - Number(a.is_default)
  )
}

/** Re-authentication for a pending sensitive action; open while one waits. */
export function StepUpDialog({
  controller,
  returnTo,
  acquireSolanaSigner,
}: StepUpDialogProps) {
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
            acquireSolanaSigner={acquireSolanaSigner}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

const METHOD_LABEL: Record<string, MessageKey> = {
  totp: "twoFactor.methods.totp",
  email: "twoFactor.methods.email",
  sms: "twoFactor.methods.sms",
}

function StepUpBody({
  controller,
  challenge,
  returnTo,
  acquireSolanaSigner,
}: {
  controller: StepUpController
  challenge: StepUpChallenge
  returnTo?: string
  acquireSolanaSigner?: () => Promise<SolanaSigner>
}) {
  const { t } = useMessages()
  const { capabilities } = useCapabilities()
  const factors = codeFactors(challenge)
  const channels = challenge.methods.filter(isChannel)
  const tabs: string[] = [
    ...(challenge.methods.includes("password") ? ["password"] : []),
    ...channels,
    ...factors.map((f) => f.id),
  ]
  const passkey = challenge.methods.includes("passkey") && webAuthnAvailable()
  const wallet = challenge.methods.includes("solana") && acquireSolanaSigner
  const providers = challenge.methods.filter((m) => !OWN_METHODS.has(m))
  const others = passkey || !!wallet || providers.length > 0
  const [tab, setTab] = useState(tabs[0] ?? "")
  const factor = factors.find((f) => f.id === tab)
  const { busy } = controller

  const providerName = (id: string) =>
    capabilities?.external_login_providers.find((p) => p.id === id)?.name ??
    id.charAt(0).toUpperCase() + id.slice(1)
  const methodLabel = (method: string) =>
    METHOD_LABEL[method] ? t(METHOD_LABEL[method]) : method

  return (
    <div className="grid gap-5">
      {tabs.length > 1 && (
        <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
          <TabsList className="w-full" aria-label={t("stepUp.chooseMethod")}>
            {tabs.map((id) => (
              <TabsTrigger key={id} value={id} disabled={busy}>
                {id === "password"
                  ? t("stepUp.methodPassword")
                  : methodLabel(factors.find((f) => f.id === id)?.method ?? id)}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      )}
      {tab === "password" && <PasswordStepUp controller={controller} />}
      {isChannel(tab) && (
        <ContactStepUp key={tab} controller={controller} channel={tab} />
      )}
      {factor && (
        <CodeStepUp
          key={factor.id}
          controller={controller}
          factor={factor}
          label={methodLabel(factor.method)}
        />
      )}
      {others && (
        <div className="grid gap-2">
          {tabs.length > 0 && (
            <div className="flex items-center gap-3 text-xs text-muted-foreground uppercase">
              <span className="h-px flex-1 bg-border" />
              {t("common.or")}
              <span className="h-px flex-1 bg-border" />
            </div>
          )}
          {passkey && (
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => void controller.withPasskey()}
            >
              <HugeiconsIcon icon={FingerPrintIcon} strokeWidth={2} />
              {t("stepUp.withPasskey")}
            </Button>
          )}
          {wallet && (
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => void controller.withSolana(wallet)}
            >
              <HugeiconsIcon icon={Wallet01Icon} strokeWidth={2} />
              {t("stepUp.withWallet")}
            </Button>
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
      {tabs.length === 0 && !others && (
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
  factor,
  label,
}: {
  controller: StepUpController
  factor: TwoFactorFactor
  label: string
}) {
  const { t } = useMessages()
  const [backup, setBackup] = useState(false)
  const [backupCode, setBackupCode] = useState("")
  const backupId = useId()
  const { state, busy, error } = controller
  const sent = state.step === "code_sent" && state.factorId === factor.id

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

  if (factor.method !== "totp" && !sent)
    return (
      <div className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          {t("stepUp.sendPrompt", { method: label.toLowerCase() })}
        </p>
        <ErrorNotice error={error} />
        <Button
          disabled={busy}
          onClick={() => void controller.sendCode(factor.id)}
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
        key={sent ? `sent:${factor.id}` : factor.id}
        prompt={
          sent
            ? t("stepUp.codeSentTo", {
                destination:
                  state.destination ??
                  factor.destination ??
                  (factor.method === "email"
                    ? t("account.twoFactor.yourEmail")
                    : label.toLowerCase()),
              })
            : t("stepUp.totpPrompt")
        }
        busy={busy}
        error={error}
        submitLabel={t("stepUp.submit")}
        onSubmit={(code) =>
          controller.withTwoFactor(code, { factorId: factor.id })
        }
        onResend={sent ? () => controller.sendCode(factor.id) : undefined}
      />
      {toggle}
    </div>
  )
}

// A code sent to the account's own proven email or phone.
function ContactStepUp({
  controller,
  channel,
}: {
  controller: StepUpController
  channel: StepUpChannel
}) {
  const { t } = useMessages()
  const { user } = useUser()
  const { state, busy, error } = controller
  const sent = state.step === "contact_code_sent" && state.channel === channel
  const destination =
    channel === "email"
      ? (user?.email ?? t("account.twoFactor.yourEmail"))
      : (user?.phone_number ?? t("stepUp.yourPhone"))

  if (!sent)
    return (
      <div className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          {t("stepUp.sendTo", { destination })}
        </p>
        <ErrorNotice error={error} />
        <Button
          disabled={busy}
          onClick={() => void controller.sendContactCode(channel)}
        >
          {busy && <Spinner />}
          {busy ? t("common.sending") : t("common.sendCode")}
        </Button>
      </div>
    )
  return (
    <CodeStep
      key={`sent:${channel}`}
      prompt={t("stepUp.codeSentTo", { destination })}
      busy={busy}
      error={error}
      submitLabel={t("stepUp.submit")}
      onSubmit={(code) => controller.withContactCode(code)}
      onResend={() => controller.sendContactCode(channel)}
    />
  )
}
