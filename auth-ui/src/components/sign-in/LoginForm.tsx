import { Key02Icon, Mail01Icon } from "@hugeicons/core-free-icons"
import { useState, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import { useLogin } from "#authui/react/useLogin"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { ForgotPasswordForm } from "./ForgotPasswordForm.tsx"
import { useSignedIn, type SignInHostProps } from "./host.ts"
import { normalizeIdentifier } from "./identifier.ts"
import type { LoginController } from "./labels.ts"
import { LoginSteps } from "./LoginSteps.tsx"
import {
  FormAlert,
  PasswordField,
  SubmitButton,
  TextButton,
  TextField,
} from "./parts.tsx"
import { ProviderButtons } from "./ProviderButtons.tsx"

export type LoginFormProps = SignInHostProps & {
  // A useLogin() owned by a parent; its onSignedIn is then the parent's.
  controller?: LoginController
  // Default: the reset form replaces this one until the user goes back.
  onForgotPassword?: (identifier: string) => void
  hideProviders?: boolean
  footer?: ReactNode
  className?: string
}

export function LoginForm(props: LoginFormProps) {
  const signedIn = useSignedIn(props)
  const own = useLogin({ onSignedIn: signedIn })
  const login = props.controller ?? own
  const [forgot, setForgot] = useState<string | null>(null)

  let body: ReactNode
  if (forgot !== null) {
    body = (
      <ForgotPasswordForm
        initialIdentifier={forgot}
        defaultPhoneCountry={props.defaultPhoneCountry}
        onBack={() => setForgot(null)}
      />
    )
  } else if (login.state.step !== "credentials") {
    body = (
      <LoginSteps
        controller={login}
        defaultPhoneCountry={props.defaultPhoneCountry}
      />
    )
  } else {
    body = (
      <Credentials
        {...props}
        login={login}
        onForgotPassword={props.onForgotPassword ?? setForgot}
      />
    )
  }
  return <AuthUiRoot className={props.className}>{body}</AuthUiRoot>
}

function Credentials({
  login,
  onForgotPassword,
  hideProviders,
  footer,
  defaultPhoneCountry,
  providers,
  renderSolana,
  returnTo,
  accountInviteToken,
}: LoginFormProps & {
  login: LoginController
  onForgotPassword: (identifier: string) => void
}) {
  const { t, error: describe } = useMessages()
  const [identifier, setIdentifier] = useState("")
  const [password, setPassword] = useState("")
  const [touched, setTouched] = useState(false)
  const { busy, error, state } = login

  const identifierError =
    touched && !identifier.trim() ? t("validation.emailOrPhoneRequired") : null
  const passwordError =
    touched && !password ? t("validation.passwordRequired") : null
  const resetRequired = error?.code === "password_reset_required"

  return (
    <div className="flex flex-col gap-5">
      <form
        className="flex flex-col gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          setTouched(true)
          if (!identifier.trim() || !password) return
          void login.signIn({
            identifier: normalizeIdentifier(identifier, defaultPhoneCountry),
            password,
          })
        }}
      >
        {state.step === "credentials" && state.recovered && !error && (
          <FormAlert tone="success">{t("signIn.recovered")}</FormAlert>
        )}
        {error && (
          <FormAlert
            action={
              resetRequired && (
                <Button
                  type="button"
                  size="sm"
                  onClick={() => onForgotPassword(identifier)}
                >
                  {t("signIn.resetRequiredAction")}
                </Button>
              )
            }
          >
            {describe(error)}
          </FormAlert>
        )}
        <TextField
          label={t("fields.emailOrPhone")}
          icon={Mail01Icon}
          name="identifier"
          type="text"
          inputMode="email"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          placeholder={t("fields.emailPlaceholder")}
          value={identifier}
          error={identifierError}
          onChange={(e) => setIdentifier(e.target.value)}
        />
        <div className="flex flex-col gap-2">
          <PasswordField
            label={t("fields.password")}
            icon={Key02Icon}
            name="password"
            autoComplete="current-password"
            value={password}
            error={passwordError}
            onChange={(e) => setPassword(e.target.value)}
          />
          <TextButton
            className="self-end text-xs"
            onClick={() => onForgotPassword(identifier.trim())}
          >
            {t("signIn.forgotPassword")}
          </TextButton>
        </div>
        <SubmitButton busy={busy}>{t("signIn.submit")}</SubmitButton>
      </form>
      {!hideProviders && (
        <ProviderButtons
          mode="login"
          providers={providers}
          renderSolana={renderSolana}
          onOutcome={login.resume}
          returnTo={returnTo}
          accountInviteToken={accountInviteToken}
          disabled={busy}
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
