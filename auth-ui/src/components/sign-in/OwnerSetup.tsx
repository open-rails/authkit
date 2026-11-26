import {
  AlertCircleIcon,
  Mail01Icon,
  ShieldUserIcon,
  UserIcon,
} from "@hugeicons/core-free-icons"
import { useEffect, useRef, useState, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import { useAuthClient, useCapabilities } from "#authui/react/context"
import { useLogin } from "#authui/react/useLogin"
import { useTask } from "#authui/react/task"
import { AuthUiRoot } from "#authui/scope"
import { LoginSteps } from "./LoginSteps.tsx"
import {
  FormAlert,
  PasswordField,
  StepHeader,
  SubmitButton,
  TextField,
} from "./parts.tsx"
import { usePasswordPolicy } from "./password.ts"

export type OwnerSetupProps = {
  // From the setup link the server logged: readSetupToken(location.hash).
  token?: string | null
  // Leaves the setup route; use the router's replace navigation.
  navigate: (to: string) => void
  // Where the signed-in owner goes. Default "/".
  fallbackPath?: string
  onSignedIn?: (result: { returnTo?: string }) => void
  defaultPhoneCountry?: string
  // Wraps the page, e.g. in the app's shell.
  layout?: (children: ReactNode) => ReactNode
  className?: string
}

// The first administrator's page (Frontend.SetupPath): the single-use link
// the server logs while nobody administers it creates the owner account
// with its own password, then signs in, enrolling a second factor first.
export function OwnerSetup({
  token,
  navigate,
  fallbackPath = "/",
  onSignedIn,
  defaultPhoneCountry,
  layout = (c) => c,
  className,
}: OwnerSetupProps) {
  const { t, error: describe } = useMessages()
  const client = useAuthClient()
  const host = useRef({ navigate, onSignedIn, fallbackPath })
  useEffect(() => {
    host.current = { navigate, onSignedIn, fallbackPath }
  })
  const login = useLogin({
    onSignedIn: ({ returnTo }) => {
      host.current.onSignedIn?.({ returnTo })
      host.current.navigate(returnTo ?? host.current.fallbackPath)
    },
  })
  const { busy, error, run } = useTask()
  const password = usePasswordPolicy()
  const { capabilities } = useCapabilities()
  const mfa = capabilities?.two_factor.mode !== "disabled"
  const [form, setForm] = useState({
    email: "",
    username: "",
    password: "",
    confirm: "",
  })
  const [checked, setChecked] = useState(false)
  const set =
    (field: keyof typeof form) => (e: { target: { value: string } }) =>
      setForm((f) => ({ ...f, [field]: e.target.value }))

  const issues = {
    email: !form.email.includes("@") ? t("validation.emailInvalid") : null,
    username: !form.username.trim() ? t("validation.usernameRequired") : null,
    password: password.issue(form.password, form.username, form.email),
    confirm:
      form.confirm !== form.password
        ? t("validation.passwordsDoNotMatch")
        : null,
  }
  const shown = (field: keyof typeof issues) => (checked ? issues[field] : null)

  let body: ReactNode
  if (login.state.step !== "credentials") {
    body = (
      <LoginSteps
        controller={login}
        defaultPhoneCountry={defaultPhoneCountry}
      />
    )
  } else if (!token) {
    body = (
      <div className="flex flex-col gap-5" role="alert">
        <StepHeader
          icon={AlertCircleIcon}
          title={t("setup.title")}
          description={t("setup.missingLink")}
        />
      </div>
    )
  } else {
    body = (
      <form
        className="flex flex-col gap-5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          setChecked(true)
          if (Object.values(issues).some(Boolean)) return
          void run(async () => {
            login.resume(
              await client.completeSetup({
                token,
                email: form.email,
                username: form.username,
                password: form.password,
              })
            )
          })
        }}
      >
        <StepHeader
          icon={ShieldUserIcon}
          title={t("setup.title")}
          description={t("setup.description")}
        />
        {error && <FormAlert>{describe(error)}</FormAlert>}
        <TextField
          label={t("fields.email")}
          icon={Mail01Icon}
          type="email"
          autoComplete="email"
          placeholder={t("fields.emailPlaceholder")}
          value={form.email}
          onChange={set("email")}
          error={shown("email")}
          autoFocus
        />
        <TextField
          label={t("fields.username")}
          icon={UserIcon}
          autoComplete="username"
          value={form.username}
          onChange={set("username")}
          error={shown("username")}
        />
        <PasswordField
          label={t("fields.password")}
          autoComplete="new-password"
          value={form.password}
          onChange={set("password")}
          hint={password.hint}
          error={shown("password")}
        />
        <PasswordField
          label={t("fields.confirmPassword")}
          autoComplete="new-password"
          value={form.confirm}
          onChange={set("confirm")}
          error={shown("confirm")}
        />
        <SubmitButton busy={busy}>{t("setup.submit")}</SubmitButton>
        {mfa && (
          <p className="text-center text-xs text-balance text-muted-foreground">
            {t("setup.mfaNote")}
          </p>
        )}
      </form>
    )
  }
  return (
    <AuthUiRoot className={className}>
      {layout(<div className="mx-auto w-full max-w-sm px-4 py-10">{body}</div>)}
    </AuthUiRoot>
  )
}
