import { Login01Icon, UserAdd01Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useEffect, useRef, useState, type ReactNode } from "react"

import { useMessages } from "#authui/i18n/context"
import type { LoginState } from "#authui/react/useLogin"
import { useLogin } from "#authui/react/useLogin"
import { useRegister } from "#authui/react/useRegister"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "#authui/ui/tabs"
import { ForgotPasswordForm } from "./ForgotPasswordForm.tsx"
import { useSignedIn, type SignInHostProps, type SignInMode } from "./host.ts"
import { LoginForm } from "./LoginForm.tsx"
import { RegisterForm } from "./RegisterForm.tsx"

export type SignInStep =
  | SignInMode
  | "forgot_password"
  | "verify_registration"
  | Exclude<LoginState["step"], "credentials">

export type SignInFlowProps = SignInHostProps & {
  initialTab?: SignInMode
  // Under the login form, e.g. a welcome line.
  footer?: ReactNode
  // Under the register form. Default: built from termsUrl/privacyUrl.
  legal?: ReactNode
  termsUrl?: string
  privacyUrl?: string
  // Current screen; "backup_codes" means signed in but not yet acknowledged.
  onStepChange?: (step: SignInStep) => void
}

function DefaultLegal({ termsUrl, privacyUrl }: SignInFlowProps) {
  const { t } = useMessages()
  if (!termsUrl && !privacyUrl) return null
  const link = (href: string, label: string) => (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  )
  return (
    <>
      {t("register.legalPrefix")}{" "}
      {termsUrl && link(termsUrl, t("register.terms"))}
      {termsUrl && privacyUrl && ` ${t("register.and")} `}
      {privacyUrl && link(privacyUrl, t("register.privacy"))}.
    </>
  )
}

// Sign in / register tabs plus every step after them, shared by the dialog
// and the inline panel.
export function SignInFlow(props: SignInFlowProps) {
  const { t } = useMessages()
  const signedIn = useSignedIn(props)
  const login = useLogin({ onSignedIn: signedIn })
  const register = useRegister({
    onSignedIn: signedIn,
    accountInviteToken: props.accountInviteToken,
  })
  const [tab, setTab] = useState<SignInMode>(props.initialTab ?? "login")
  const [forgot, setForgot] = useState<string | null>(null)

  const step: SignInStep =
    forgot !== null
      ? "forgot_password"
      : login.state.step !== "credentials"
        ? login.state.step
        : register.state.step === "verify"
          ? "verify_registration"
          : tab
  const onStepChange = useRef(props.onStepChange)
  useEffect(() => {
    onStepChange.current = props.onStepChange
  })
  useEffect(() => onStepChange.current?.(step), [step])

  const host = {
    returnTo: props.returnTo,
    defaultPhoneCountry: props.defaultPhoneCountry,
    providers: props.providers,
    renderSolana: props.renderSolana,
    accountInviteToken: props.accountInviteToken,
  }

  if (forgot !== null)
    return (
      <ForgotPasswordForm
        initialIdentifier={forgot}
        defaultPhoneCountry={props.defaultPhoneCountry}
        onBack={() => setForgot(null)}
      />
    )
  if (login.state.step !== "credentials")
    return <LoginForm {...host} controller={login} />

  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as SignInMode)}>
      {register.state.step !== "verify" && (
        <TabsList
          aria-label={t("signIn.tabsLabel")}
          className="mb-3 h-10! w-full"
        >
          <TabsTrigger value="login">
            <HugeiconsIcon icon={Login01Icon} strokeWidth={2} />
            {t("signIn.title")}
          </TabsTrigger>
          <TabsTrigger value="register">
            <HugeiconsIcon icon={UserAdd01Icon} strokeWidth={2} />
            {t("register.title")}
          </TabsTrigger>
        </TabsList>
      )}
      <TabsContent value="login" keepMounted>
        <LoginForm
          {...host}
          controller={login}
          onForgotPassword={setForgot}
          footer={props.footer}
        />
      </TabsContent>
      <TabsContent value="register" keepMounted>
        <RegisterForm
          {...host}
          controller={register}
          loginController={login}
          onSignIn={() => {
            register.reset()
            setTab("login")
          }}
          legal={
            props.legal ??
            (props.termsUrl || props.privacyUrl ? (
              <DefaultLegal {...props} />
            ) : null)
          }
        />
      </TabsContent>
    </Tabs>
  )
}
