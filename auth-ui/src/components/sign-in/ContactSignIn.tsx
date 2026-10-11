import { Mail01Icon } from "@hugeicons/core-free-icons"
import { useEffect, useState, type ReactNode } from "react"

import {
  conditionalMediationAvailable,
  webAuthnAvailable,
} from "#authui/client/webauthn"
import { useMessages } from "#authui/i18n/context"
import { useCapabilities } from "#authui/react/context"
import { useLogin } from "#authui/react/useLogin"
import { AuthUiRoot } from "#authui/scope"
import { useSignedIn, type SignInHostProps } from "./host.ts"
import { identifierKind, normalizeIdentifier } from "./identifier.ts"
import type { LoginController } from "./labels.ts"
import { LoginSteps } from "./LoginSteps.tsx"
import { FormAlert, StepHeader, SubmitButton, TextField } from "./parts.tsx"
import { ProviderButtons } from "./ProviderButtons.tsx"

export type ContactSignInProps = SignInHostProps & {
  // A useLogin() owned by a parent; its onSignedIn is then the parent's.
  controller?: LoginController
  // Pre-fills the field, as an OAuth client's login_hint does; it proves
  // nothing.
  initialIdentifier?: string
  hideProviders?: boolean
  footer?: ReactNode
  className?: string
}

// Contact-first sign-in, as at Shop and Link: an email or phone, then the
// code sent there, or a saved passkey from the field's autofill. A new
// contact signs up after accepting the host's agreements, and is offered a
// passkey; every later step (second factor, new device) follows.
export function ContactSignIn(props: ContactSignInProps) {
  const signedIn = useSignedIn(props)
  const own = useLogin({ onSignedIn: signedIn })
  const login = props.controller ?? own
  return (
    <AuthUiRoot className={props.className}>
      {login.state.step === "credentials" ? (
        <ContactEntry {...props} login={login} />
      ) : (
        <LoginSteps
          controller={login}
          defaultPhoneCountry={props.defaultPhoneCountry}
        />
      )}
    </AuthUiRoot>
  )
}

function ContactEntry({
  login,
  initialIdentifier,
  defaultPhoneCountry,
  returnTo,
  inviteCode,
  hideProviders,
  providers,
  renderSolana,
  footer,
}: ContactSignInProps & { login: LoginController }) {
  const { t, error: describe } = useMessages()
  const { capabilities } = useCapabilities()
  const passkeys = !!capabilities?.passkeys.login && webAuthnAvailable()
  const [value, setValue] = useState(initialIdentifier ?? "")
  const [touched, setTouched] = useState(false)
  const { busy, error, autofillPasskey } = login

  // The field's autofill offers saved passkeys while the form is shown.
  useEffect(() => {
    if (!passkeys) return
    const abort = new AbortController()
    void conditionalMediationAvailable().then((ok) => {
      if (ok && !abort.signal.aborted) void autofillPasskey(abort.signal)
    })
    return () => abort.abort()
  }, [passkeys, autofillPasskey])

  const kind = identifierKind(value)
  const invalid =
    touched && (!value.trim() || kind === "other")
      ? t("validation.emailOrPhoneRequired")
      : null

  return (
    <div className="flex flex-col gap-5">
      <form
        className="flex flex-col gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          setTouched(true)
          if (!value.trim() || kind === "other") return
          void login.sendCode(normalizeIdentifier(value, defaultPhoneCountry), {
            returnTo,
            inviteCode,
          })
        }}
      >
        <StepHeader
          title={t("contactSignIn.title")}
          description={t("contactSignIn.description")}
        />
        {error && <FormAlert>{describe(error)}</FormAlert>}
        <TextField
          label={t("fields.emailOrPhone")}
          icon={Mail01Icon}
          name="identifier"
          type="text"
          inputMode="email"
          autoComplete="username webauthn"
          autoCapitalize="none"
          spellCheck={false}
          placeholder={t("fields.emailPlaceholder")}
          value={value}
          error={invalid}
          onChange={(e) => setValue(e.target.value)}
        />
        <SubmitButton busy={busy}>{t("common.continue")}</SubmitButton>
      </form>
      {!hideProviders && (
        <ProviderButtons
          mode="login"
          providers={providers}
          renderSolana={renderSolana}
          onOutcome={login.resume}
          returnTo={returnTo}
          inviteCode={inviteCode}
          disabled={busy}
          onPasskey={
            passkeys ? () => void login.signInWithPasskey() : undefined
          }
        />
      )}
      {footer && (
        <div className="text-center text-xs text-muted-foreground">
          {footer}
        </div>
      )}
    </div>
  )
}
