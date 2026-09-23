/* eslint-disable react-refresh/only-export-components */
// Minimal host for react.spec.ts, built against the packaged dist/ entries.
import { useState } from "react"
import { createRoot } from "react-dom/client"

import { createAuthClient } from "../../dist/client.js"
import {
  AuthProvider,
  useLogin,
  useRegister,
  useSession,
  useStepUp,
  useTwoFactorSettings,
  useUser,
} from "../../dist/react.js"

const client = createAuthClient()
const sessionChanges: string[] = []
Object.assign(window, { sessionChanges })

function Field({ id }: { id: string }) {
  return <input data-testid={id} name={id} />
}

const value = (form: HTMLFormElement, id: string) =>
  (form.elements.namedItem(id) as HTMLInputElement).value

function Status() {
  const session = useSession()
  const { user } = useUser()
  return (
    <p>
      <span data-testid="status">{session.status}</span>
      <span data-testid="email">{user?.email ?? ""}</span>
    </p>
  )
}

function Register() {
  const reg = useRegister()
  if (reg.state.step === "form")
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault()
          const f = e.currentTarget
          void reg.register({
            identifier: value(f, "reg-identifier"),
            username: value(f, "reg-username"),
            password: value(f, "reg-password"),
          })
        }}
      >
        <Field id="reg-identifier" />
        <Field id="reg-username" />
        <Field id="reg-password" />
        <button>register</button>
      </form>
    )
  if (reg.state.step === "verify")
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void reg.verify(value(e.currentTarget, "reg-code"))
        }}
      >
        <Field id="reg-code" />
        <button>verify registration</button>
      </form>
    )
  return <p data-testid="register-step">{reg.state.step}</p>
}

function Login() {
  const login = useLogin()
  const { state } = login
  return (
    <section>
      <p data-testid="login-step">{state.step}</p>
      <p data-testid="login-error">{login.error?.code ?? ""}</p>
      {state.step === "credentials" && (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            const f = e.currentTarget
            void login.signIn({
              identifier: value(f, "login-identifier"),
              password: value(f, "login-password"),
            })
          }}
        >
          <Field id="login-identifier" />
          <Field id="login-password" />
          <button>sign in</button>
        </form>
      )}
      {state.step === "two_factor" && (
        <>
          <p data-testid="login-method">{state.challenge.method}</p>
          {state.challenge.availableFactors.map((f) => (
            <button
              key={f.id}
              data-testid={`factor-${f.method}`}
              onClick={() => void login.sendTwoFactorCode(f.id)}
            >
              use {f.method}
            </button>
          ))}
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void login.verifyTwoFactor(value(e.currentTarget, "login-code"))
            }}
          >
            <Field id="login-code" />
            <button>verify code</button>
          </form>
          <button onClick={() => void login.sendTwoFactorCode()}>
            resend code
          </button>
        </>
      )}
    </section>
  )
}

function Security() {
  const stepUp = useStepUp()
  const tf = useTwoFactorSettings({ guard: stepUp.guard })
  const [code, setCode] = useState("")
  const { enrollment } = tf
  return (
    <section>
      <p data-testid="factors">
        {(tf.status?.factors ?? []).map((f) => f.method).join(",")}
      </p>
      <p data-testid="tf-error">{tf.error?.code ?? ""}</p>
      <button onClick={() => void tf.start({ method: "totp" })}>
        start totp
      </button>
      <button onClick={() => void tf.start({ method: "email" })}>
        add email factor
      </button>
      {enrollment.step === "totp" && (
        <p data-testid="totp-secret">{enrollment.secret}</p>
      )}
      {enrollment.step === "backup_codes" && (
        <>
          <p data-testid="backup-codes">{enrollment.codes.join(",")}</p>
          <button onClick={tf.dismiss}>saved them</button>
        </>
      )}
      <input
        data-testid="tf-code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <button onClick={() => void tf.confirm(code)}>confirm factor</button>

      <p data-testid="stepup-step">{stepUp.state.step}</p>
      {stepUp.state.step !== "idle" && (
        <div role="dialog">
          <p data-testid="stepup-methods">
            {stepUp.state.challenge.methods.join(",")}
          </p>
          <p data-testid="stepup-error">{stepUp.error?.code ?? ""}</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void stepUp.withTwoFactor(value(e.currentTarget, "stepup-code"), {
                method: "totp",
              })
            }}
          >
            <Field id="stepup-code" />
            <button>step up</button>
          </form>
          <button onClick={stepUp.cancel}>cancel step-up</button>
        </div>
      )}
      <button onClick={() => void client.signOut()}>sign out</button>
    </section>
  )
}

function App() {
  const session = useSession()
  return (
    <main>
      <Status />
      {session.status === "anonymous" && (
        <>
          <Register />
          <Login />
        </>
      )}
      {session.status === "authenticated" && <Security />}
    </main>
  )
}

const root = document.createElement("div")
document.body.append(root)
createRoot(root).render(
  <AuthProvider
    client={client}
    onSessionChange={(s) => sessionChanges.push(s.status)}
  >
    <App />
  </AuthProvider>
)
