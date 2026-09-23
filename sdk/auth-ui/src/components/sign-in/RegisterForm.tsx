import {
  Cancel01Icon,
  CheckmarkCircle02Icon,
  Key02Icon,
  Mail01Icon,
  MailSend01Icon,
  SparklesIcon,
  Tick02Icon,
  UserIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useEffect, useState, type ReactNode } from "react"

import type { Availability, PasswordPolicy } from "#authui/client/types"
import { useMessages } from "#authui/i18n/context"
import { useCapabilities } from "#authui/react/context"
import { useLogin } from "#authui/react/useLogin"
import { useRegister, type RegisterInput } from "#authui/react/useRegister"
import type { LoginContinuation } from "#authui/client/continuation"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { InputGroupButton } from "#authui/ui/input-group"
import { Spinner } from "#authui/ui/spinner"
import { useCooldown } from "./cooldown.ts"
import { useSignedIn, type SignInHostProps } from "./host.ts"
import {
  identifierKind,
  isE164,
  isEmail,
  normalizeIdentifier,
} from "./identifier.ts"
import type { LoginController, RegisterController } from "./labels.ts"
import { LoginSteps } from "./LoginSteps.tsx"
import {
  CodeField,
  FormAlert,
  PasswordField,
  StepHeader,
  SubmitButton,
  TextButton,
  TextField,
} from "./parts.tsx"
import { ProviderButtons } from "./ProviderButtons.tsx"

const PASSWORD_MIN = 8

const IDENTIFIER_CODES = new Set([
  "email_in_use",
  "phone_in_use",
  "invalid_identifier",
  "invalid_email",
  "invalid_phone_number",
  "phone_number_must_be_e164",
  "email_registration_unavailable",
  "phone_registration_unavailable",
])
const PASSWORD_CODES = new Set([
  "password_too_short",
  "password_too_long",
  "password_too_common",
  "password_requirements_unmet",
  "password_contains_identifier",
  "invalid_password",
])
const fieldOf = (code: string) =>
  IDENTIFIER_CODES.has(code)
    ? "identifier"
    : code.startsWith("username_") || code === "owner_slug_taken"
      ? "username"
      : PASSWORD_CODES.has(code)
        ? "password"
        : null

const CLASSES = [
  ["require_uppercase", /\p{Lu}/u],
  ["require_lowercase", /\p{Ll}/u],
  ["require_digit", /\p{Nd}/u],
  ["require_symbol", /[^\p{L}\p{Nd}]/u],
] as const

// Client-side mirror of the advertised policy; AuthKit stays authoritative.
function passwordIssue(policy: PasswordPolicy | undefined, value: string) {
  const min = policy?.min_length ?? PASSWORD_MIN
  if (value.length < min) return { code: "password_too_short", min }
  if (policy?.max_length && value.length > policy.max_length)
    return { code: "password_too_long", min }
  if (CLASSES.some(([key, re]) => policy?.[key] && !re.test(value)))
    return { code: "password_requirements_unmet", min }
  return null
}

function usernameIssue(
  policy:
    { min_length: number; max_length: number; pattern: string } | undefined,
  value: string
) {
  if (!policy || !value) return null
  if (value.length < policy.min_length) return "username_too_short"
  if (value.length > policy.max_length) return "username_too_long"
  try {
    if (!new RegExp(policy.pattern).test(value))
      return /^\p{L}/u.test(value)
        ? "username_invalid_characters"
        : "username_must_start_with_letter"
  } catch {
    // an unparsable pattern is left to the server
  }
  return null
}

export type RegisterFormProps = SignInHostProps & {
  // A useRegister() owned by a parent; its onSignedIn is then the parent's.
  controller?: RegisterController
  // Verification signed in but AuthKit wants more (e.g. forced 2FA). Default:
  // this form runs the login steps itself.
  onContinuation?: (continuation: LoginContinuation) => void
  // Shared with a sibling LoginForm so provider/wallet sign-up continue there.
  loginController?: LoginController
  // Offered when registration finished without a session.
  onSignIn?: () => void
  hideProviders?: boolean
  legal?: ReactNode
  className?: string
}

export function RegisterForm(props: RegisterFormProps) {
  const signedIn = useSignedIn(props)
  const own = useRegister({
    onSignedIn: signedIn,
    accountInviteToken: props.accountInviteToken,
  })
  const register = props.controller ?? own
  const ownLogin = useLogin({ onSignedIn: signedIn })
  const login = props.loginController ?? ownLogin
  const { state, reset } = register
  const { onContinuation } = props
  const resume = login.resume

  useEffect(() => {
    if (state.step !== "continuation") return
    ;(onContinuation ?? resume)(state.continuation)
    reset()
  }, [state, onContinuation, resume, reset])

  let body: ReactNode
  if (!onContinuation && login.state.step !== "credentials") {
    body = (
      <LoginSteps
        controller={login}
        defaultPhoneCountry={props.defaultPhoneCountry}
      />
    )
  } else if (state.step === "verify") {
    body = <VerifyRegistration register={register} />
  } else if (state.step === "done" && !state.signedIn) {
    body = <Registered onSignIn={props.onSignIn} />
  } else {
    body = <RegisterFields {...props} register={register} login={login} />
  }
  return <AuthUiRoot className={props.className}>{body}</AuthUiRoot>
}

type Check = { key: string; out: Availability }
type Status = "checking" | "available" | { code: string } | null

function useAvailability(
  register: RegisterController,
  identifier: string,
  username: string,
  defaultPhoneCountry?: string
) {
  const kind = identifierKind(identifier)
  const normalized = normalizeIdentifier(identifier, defaultPhoneCountry)
  const query: { username?: string; email?: string; phoneNumber?: string } = {}
  if (kind === "email" && isEmail(normalized)) query.email = normalized
  if (kind === "phone" && isE164(normalized)) query.phoneNumber = normalized
  if (username.trim()) query.username = username.trim()
  const key = JSON.stringify(query)
  const [check, setCheck] = useState<Check | null>(null)
  const { checkAvailability } = register

  useEffect(() => {
    if (key === "{}") return
    const timer = setTimeout(async () => {
      const out = await checkAvailability(JSON.parse(key))
      if (out) setCheck({ key, out })
    }, 400)
    return () => clearTimeout(timer)
  }, [key, checkAvailability])

  const current = check?.key === key ? check.out : null
  const status = (
    asked: boolean,
    field: { available: boolean; error?: string } | undefined,
    fallback: string
  ): Status => {
    if (!asked) return null
    if (!current) return "checking"
    if (!field || field.available) return "available"
    return { code: field.error || fallback }
  }
  return {
    identifier: status(
      !!(query.email || query.phoneNumber),
      query.email ? current?.email : current?.phone_number,
      query.email ? "email_in_use" : "phone_in_use"
    ),
    username: status(!!query.username, current?.username, "username_in_use"),
  }
}

function StatusIcon({ status }: { status: Status }) {
  if (!status) return null
  if (status === "checking")
    return <Spinner className="text-muted-foreground" />
  if (status === "available")
    return (
      <HugeiconsIcon
        icon={Tick02Icon}
        strokeWidth={2}
        className="text-success"
        aria-hidden="true"
      />
    )
  return (
    <HugeiconsIcon
      icon={Cancel01Icon}
      strokeWidth={2}
      className="text-destructive"
      aria-hidden="true"
    />
  )
}

function generatePassword(): string {
  const sets = [
    "abcdefghijkmnopqrstuvwxyz",
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "23456789",
    "!@#$%^&*-_",
  ]
  const all = sets.join("")
  const rand = (n: number) => crypto.getRandomValues(new Uint32Array(1))[0] % n
  const chars = sets.map((s) => s[rand(s.length)])
  while (chars.length < 16) chars.push(all[rand(all.length)])
  for (let i = chars.length - 1; i > 0; i--) {
    const j = rand(i + 1)
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }
  return chars.join("")
}

function RegisterFields({
  register,
  login,
  hideProviders,
  legal,
  defaultPhoneCountry,
  providers,
  renderSolana,
  returnTo,
  accountInviteToken,
}: RegisterFormProps & {
  register: RegisterController
  login: LoginController
}) {
  const { t, error: describe } = useMessages()
  const { capabilities } = useCapabilities()
  const passwordPolicy = capabilities?.password
  const usernamePolicy = capabilities?.username
  const minPassword = passwordPolicy?.min_length ?? PASSWORD_MIN
  const [identifier, setIdentifier] = useState("")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [revealed, setRevealed] = useState(false)
  const [submitted, setSubmitted] = useState<RegisterInput | null>(null)
  const availability = useAvailability(
    register,
    identifier,
    username,
    defaultPhoneCountry
  )
  const { busy, error } = register
  const normalized = normalizeIdentifier(identifier, defaultPhoneCountry)

  // Server errors stick to their field until that field changes.
  const serverField = error ? fieldOf(error.code) : null
  const server = (field: "identifier" | "username" | "password") =>
    serverField === field &&
    submitted &&
    (field === "identifier"
      ? submitted.identifier === normalized
      : field === "username"
        ? submitted.username === username.trim()
        : submitted.password === password)
      ? describe(error)
      : null
  const unavailable = (s: Status) =>
    s && typeof s === "object" ? describe(s.code) : null

  const touched = submitted !== null
  const identifierError =
    server("identifier") ??
    unavailable(availability.identifier) ??
    (touched && !identifier.trim()
      ? t("validation.emailOrPhoneRequired")
      : touched && identifierKind(identifier) === "other"
        ? t("validation.emailInvalid")
        : null)
  const localUsername = usernameIssue(usernamePolicy, username.trim())
  const localPassword = passwordIssue(passwordPolicy, password)
  const usernameError =
    server("username") ??
    unavailable(availability.username) ??
    (touched && !username.trim()
      ? t("validation.usernameRequired")
      : touched && localUsername
        ? describe(localUsername)
        : null)
  const passwordError =
    server("password") ??
    (touched && localPassword
      ? localPassword.code === "password_too_short"
        ? t("validation.passwordMinLength", { min: localPassword.min })
        : describe(localPassword.code)
      : null)

  return (
    <div className="flex flex-col gap-5">
      <form
        className="flex flex-col gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          const input = {
            identifier: normalized,
            username: username.trim(),
            password,
          }
          setSubmitted(input)
          if (
            !input.identifier ||
            identifierKind(input.identifier) === "other" ||
            !input.username ||
            localUsername ||
            localPassword ||
            unavailable(availability.identifier) ||
            unavailable(availability.username)
          )
            return
          void register.register(input)
        }}
      >
        {error && !serverField && <FormAlert>{describe(error)}</FormAlert>}
        <TextField
          id="authui-register-identifier"
          label={t("fields.emailOrPhone")}
          icon={Mail01Icon}
          name="email"
          type="text"
          inputMode="email"
          autoComplete="email"
          autoCapitalize="none"
          spellCheck={false}
          placeholder={t("fields.emailPlaceholder")}
          value={identifier}
          error={identifierError}
          trailing={<StatusIcon status={availability.identifier} />}
          onChange={(e) => setIdentifier(e.target.value)}
        />
        <TextField
          id="authui-register-username"
          label={t("fields.username")}
          icon={UserIcon}
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          value={username}
          error={usernameError}
          trailing={<StatusIcon status={availability.username} />}
          onChange={(e) => setUsername(e.target.value)}
        />
        <PasswordField
          id="authui-register-password"
          label={t("fields.password")}
          icon={Key02Icon}
          name="new-password"
          autoComplete="new-password"
          value={password}
          error={passwordError}
          hint={t("register.passwordHint", { min: minPassword })}
          revealed={revealed}
          onRevealedChange={setRevealed}
          onChange={(e) => setPassword(e.target.value)}
          extra={
            <InputGroupButton
              size="icon-xs"
              tabIndex={-1}
              aria-label={t("fields.generatePassword")}
              title={t("fields.generatePassword")}
              onClick={() => {
                setPassword(generatePassword())
                setRevealed(true)
              }}
            >
              <HugeiconsIcon icon={SparklesIcon} />
            </InputGroupButton>
          }
        />
        <SubmitButton busy={busy}>{t("register.submit")}</SubmitButton>
      </form>
      {!hideProviders && (
        <ProviderButtons
          mode="register"
          providers={providers}
          renderSolana={renderSolana}
          onOutcome={login.resume}
          returnTo={returnTo}
          accountInviteToken={accountInviteToken}
          disabled={busy}
        />
      )}
      {legal && (
        <div className="text-center text-xs text-balance text-muted-foreground [&_a]:underline [&_a]:underline-offset-3 [&_a:hover]:text-foreground">
          {legal}
        </div>
      )}
    </div>
  )
}

function VerifyRegistration({ register }: { register: RegisterController }) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = register
  const [code, setCode] = useState("")
  const [resent, setResent] = useState(false)
  const [abandoning, setAbandoning] = useState(false)
  const cooldown = useCooldown(30, true)
  if (state.step !== "verify") return null
  const verify = (value = code) => {
    if (!value.trim() || busy) return
    setCode("")
    setResent(false)
    void register.verify(value)
  }
  const resend = async () => {
    setResent(false)
    await register.resend()
    setResent(true)
    cooldown.start()
  }

  if (abandoning)
    return (
      <div className="flex flex-col gap-5">
        <StepHeader
          title={t("verify.cancelConfirmTitle")}
          description={t("verify.cancelBody", { identifier: state.identifier })}
        />
        {error && <FormAlert>{describe(error)}</FormAlert>}
        <Button
          variant="destructive"
          size="lg"
          className="w-full"
          disabled={busy}
          onClick={() => void register.abandon()}
        >
          {busy && <Spinner />}
          {t("verify.cancelRegistration")}
        </Button>
        <Button
          variant="ghost"
          className="w-full"
          disabled={busy}
          onClick={() => setAbandoning(false)}
        >
          {t("verify.keepRegistration")}
        </Button>
      </div>
    )

  return (
    <form
      className="flex flex-col gap-5"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        verify()
      }}
    >
      <StepHeader
        icon={MailSend01Icon}
        title={
          state.channel === "phone"
            ? t("verify.titlePhone")
            : t("verify.titleEmail")
        }
        description={`${t("verify.codeSentTo", { destination: state.identifier })} ${t("verify.instructions")}`}
      />
      {error && <FormAlert>{describe(error)}</FormAlert>}
      {resent && !error && !busy && (
        <FormAlert tone="success">{t("verify.codeSent")}</FormAlert>
      )}
      <CodeField
        label={t("fields.verificationCode")}
        value={code}
        onChange={setCode}
        onComplete={verify}
        invalid={!!error}
        disabled={busy}
      />
      <SubmitButton busy={busy} disabled={!code.trim()}>
        {state.channel === "phone"
          ? t("verify.submitPhone")
          : t("verify.submitEmail")}
      </SubmitButton>
      <p className="flex flex-wrap items-center justify-center gap-x-1.5 text-sm text-muted-foreground">
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
      <TextButton
        className="self-center text-muted-foreground"
        disabled={busy}
        onClick={() => setAbandoning(true)}
      >
        {t("verify.cancelRegistration")}
      </TextButton>
    </form>
  )
}

function Registered({ onSignIn }: { onSignIn?: () => void }) {
  const { t } = useMessages()
  return (
    <div className="flex flex-col gap-5" role="status">
      <StepHeader
        icon={CheckmarkCircle02Icon}
        title={t("verify.success")}
        description={t("register.complete")}
      />
      {onSignIn && (
        <Button size="lg" className="w-full" onClick={onSignIn}>
          {t("signIn.submit")}
        </Button>
      )}
    </div>
  )
}
