import {
  FingerPrintIcon,
  LegalDocument01Icon,
  MailSend01Icon,
} from "@hugeicons/core-free-icons"
import { useId, useState } from "react"

import type {
  Agreement,
  OAuthThirdParty,
  ScopeDescription,
} from "#authui/client/types"
import { useMessages } from "#authui/i18n/context"
import { Button } from "#authui/ui/button"
import { Checkbox } from "#authui/ui/checkbox"
import { useCooldown, useSpentCode } from "./cooldown.ts"
import type { LoginController } from "./labels.ts"
import {
  CodeField,
  FormAlert,
  StepHeader,
  SubmitButton,
  TextButton,
} from "./parts.tsx"

const RESEND_SECONDS = 30

// A document's name from its key: "network-terms" reads "Network terms".
const documentName = (key: string) => {
  const words = key.replace(/[-_]+/g, " ").trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

// The code a contact-first sign-in sent to an email or phone.
export function ContactCode({ controller }: { controller: LoginController }) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  const [code, setCode] = useState("")
  const [resent, setResent] = useState(false)
  const cooldown = useCooldown(RESEND_SECONDS, state.step === "code")
  const spentCode = useSpentCode(error)
  if (state.step !== "code") return null
  const submit = (value = code) => {
    const trimmed = value.trim()
    if (!trimmed || busy) return
    setCode("")
    setResent(false)
    void controller.confirmCode(trimmed)
  }
  const resend = async () => {
    setCode("")
    setResent(false)
    spentCode.renew()
    await controller.resendCode()
    setResent(true)
    cooldown.start()
  }
  return (
    <form
      className="flex flex-col gap-5"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        submit()
      }}
    >
      <StepHeader
        icon={MailSend01Icon}
        title={t("contactSignIn.codeTitle")}
        description={t("contactSignIn.codeSentTo", {
          destination: state.identifier,
        })}
      />
      {error && <FormAlert>{describe(error)}</FormAlert>}
      {resent && !error && !busy && (
        <FormAlert tone="success">{t("challenge.codeResent")}</FormAlert>
      )}
      <CodeField
        label={t("fields.verificationCode")}
        value={code}
        onChange={setCode}
        onComplete={submit}
        invalid={!!error}
        disabled={busy || spentCode.spent}
      />
      <SubmitButton busy={busy} disabled={!code.trim()}>
        {t("common.continue")}
      </SubmitButton>
      <p className="flex items-center justify-center gap-1.5 text-sm text-muted-foreground">
        {t("verify.didntReceive")}
        <TextButton
          disabled={busy || cooldown.left > 0}
          onClick={() => void resend()}
        >
          {cooldown.left > 0
            ? t("common.resendIn", { seconds: cooldown.left })
            : t("verify.resend")}
        </TextButton>
      </p>
      <Button
        type="button"
        variant="ghost"
        className="w-full"
        disabled={busy}
        onClick={controller.reset}
      >
        {t("contactSignIn.useDifferent")}
      </Button>
    </form>
  )
}

// Documents to read, tick and accept.
export function AgreementsForm({
  agreements,
  signUp,
  busy,
  error,
  onAccept,
  onBack,
}: {
  agreements: readonly Agreement[]
  // A sign-up's ("Create account"), or documents due ("Accept and
  // continue").
  signUp?: boolean
  busy: boolean
  error: unknown
  onAccept: () => void
  onBack: () => void
}) {
  const { t, error: describe } = useMessages()
  const [agreed, setAgreed] = useState(false)
  const id = useId()
  return (
    <form
      className="flex flex-col gap-5"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        if (agreed && !busy) onAccept()
      }}
    >
      <StepHeader
        icon={LegalDocument01Icon}
        title={t(signUp ? "agreements.signUpTitle" : "agreements.dueTitle")}
        description={t(
          signUp ? "agreements.signUpDescription" : "agreements.dueDescription"
        )}
      />
      {!!error && <FormAlert>{describe(error)}</FormAlert>}
      <ul className="flex flex-col gap-1.5 text-sm">
        {agreements.map((a) => (
          <li key={a.key}>
            <a href={a.url} target="_blank" rel="noopener noreferrer">
              {documentName(a.key)}
            </a>
          </li>
        ))}
      </ul>
      <label htmlFor={id} className="flex items-start gap-2.5 text-sm">
        <Checkbox
          id={id}
          checked={agreed}
          disabled={busy}
          onCheckedChange={(v) => setAgreed(v === true)}
        />
        <span>{t("agreements.accept")}</span>
      </label>
      <SubmitButton busy={busy} disabled={!agreed}>
        {t(signUp ? "agreements.createAccount" : "agreements.continue")}
      </SubmitButton>
      <Button
        type="button"
        variant="ghost"
        className="w-full"
        disabled={busy}
        onClick={onBack}
      >
        {t(signUp ? "common.back" : "agreements.decline")}
      </Button>
    </form>
  )
}

// The documents a sign-up accepts, or a sign-in found due.
export function AgreementsStep({
  controller,
}: {
  controller: LoginController
}) {
  const { state, busy, error } = controller
  if (state.step !== "signup_agreements" && state.step !== "agreements")
    return null
  const signUp = state.step === "signup_agreements"
  return (
    <AgreementsForm
      key={state.step}
      agreements={state.agreements}
      signUp={signUp}
      busy={busy}
      error={error}
      onAccept={() =>
        void (signUp
          ? controller.acceptSignUp()
          : controller.acceptAgreements())
      }
      onBack={() =>
        signUp ? controller.reset() : void controller.declineAgreements()
      }
    />
  )
}

// After a code sign-up: a passkey makes the next sign-in one tap.
export function PasskeyOffer({ controller }: { controller: LoginController }) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  if (state.step !== "passkey_offer") return null
  return (
    <div className="flex flex-col gap-5">
      <StepHeader
        icon={FingerPrintIcon}
        title={t("passkeyOffer.title")}
        description={t("passkeyOffer.description")}
      />
      {error && <FormAlert>{describe(error)}</FormAlert>}
      <Button
        size="lg"
        className="w-full"
        disabled={busy}
        onClick={() => void controller.addPasskey()}
      >
        {t("passkeyOffer.add")}
      </Button>
      <Button
        variant="ghost"
        className="w-full"
        disabled={busy}
        onClick={controller.skipPasskey}
      >
        {t("passkeyOffer.skip")}
      </Button>
    </div>
  )
}

// A sign-up form's "I agree" box, the documents linked.
export function AgreementCheck({
  agreements,
  checked,
  disabled,
  invalid,
  onChange,
}: {
  agreements: readonly Agreement[]
  checked: boolean
  disabled?: boolean
  invalid?: boolean
  onChange: (checked: boolean) => void
}) {
  const { t } = useMessages()
  const id = useId()
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="flex items-start gap-2.5 text-sm">
        <Checkbox
          id={id}
          checked={checked}
          disabled={disabled}
          aria-invalid={invalid || undefined}
          onCheckedChange={(v) => onChange(v === true)}
        />
        <span>
          {t("agreements.agreeTo")}{" "}
          {agreements.map((a, i) => (
            <span key={a.key}>
              {i > 0 && ", "}
              <a
                href={a.url}
                target="_blank"
                rel="noopener noreferrer"
                className="underline underline-offset-3"
              >
                {documentName(a.key)}
              </a>
            </span>
          ))}
        </span>
      </label>
      {invalid && (
        <p className="text-xs text-destructive" role="alert">
          {t("agreements.required")}
        </p>
      )}
    </div>
  )
}

// OpenID's own scopes, described by the interface; a deployment's scopes
// carry their description.
const STANDARD_SCOPES = ["openid", "email", "phone", "profile"] as const

// A group client's consent screen (OIDC Core 3.1.2.4): who asks, through
// which group, where the browser returns, and what each scope allows.
export function ConsentForm({
  clientName,
  thirdParty,
  scopes,
  busy,
  error,
  onAllow,
  onDeny,
}: {
  clientName: string
  thirdParty: OAuthThirdParty | null
  scopes: readonly ScopeDescription[]
  busy: boolean
  error: unknown
  onAllow: () => void
  onDeny: () => void
}) {
  const { t, error: describe } = useMessages()
  const name = thirdParty?.group_name ?? clientName
  const describeScope = (s: ScopeDescription) =>
    s.description ||
    ((STANDARD_SCOPES as readonly string[]).includes(s.name)
      ? t(`consent.scopes.${s.name as (typeof STANDARD_SCOPES)[number]}`)
      : s.name)
  return (
    <div className="flex flex-col gap-5">
      {thirdParty?.logo_uri && (
        <img
          src={thirdParty.logo_uri}
          alt=""
          className="mx-auto size-12 rounded-lg object-contain"
        />
      )}
      <StepHeader
        title={t("consent.title", { client: name })}
        description={
          thirdParty?.group_name && thirdParty.group_name !== clientName
            ? t("consent.through", { client: clientName })
            : undefined
        }
      />
      {!!error && <FormAlert>{describe(error)}</FormAlert>}
      <div className="flex flex-col gap-2 text-sm">
        <p className="font-medium">{t("consent.wants")}</p>
        <ul className="flex list-disc flex-col gap-1 ps-5">
          {scopes.map((s) => (
            <li key={s.name}>{describeScope(s)}</li>
          ))}
        </ul>
      </div>
      {thirdParty && (
        <p className="text-xs text-muted-foreground">
          {t("consent.returnsTo", { host: thirdParty.redirect_host })}{" "}
          {thirdParty.policy_uri && (
            <a
              href={thirdParty.policy_uri}
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-3"
            >
              {t("consent.privacy")}
            </a>
          )}
          {thirdParty.policy_uri && thirdParty.tos_uri && " · "}
          {thirdParty.tos_uri && (
            <a
              href={thirdParty.tos_uri}
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-3"
            >
              {t("consent.terms")}
            </a>
          )}
        </p>
      )}
      <Button size="lg" className="w-full" disabled={busy} onClick={onAllow}>
        {t("consent.allow")}
      </Button>
      <Button
        variant="ghost"
        className="w-full"
        disabled={busy}
        onClick={onDeny}
      >
        {t("consent.deny")}
      </Button>
    </div>
  )
}
