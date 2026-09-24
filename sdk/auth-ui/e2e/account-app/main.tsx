/* eslint-disable react-refresh/only-export-components */
// Host page for account.ui.spec.ts: the styled account panels on a real AuthKit.
import { useState } from "react"
import { createRoot } from "react-dom/client"

import { AccountSecurity, AuthUiProvider } from "../../dist/index.js"
import { createAuthClient } from "../../dist/client.js"
import { AuthProvider, useSession } from "../../dist/react.js"
import { SolanaLinkRow } from "../../dist/solana.js"

const params = new URLSearchParams(location.search)
const theme = params.get("theme") === "dark" ? "dark" : "light"
const client = createAuthClient()
const events: string[] = []
Object.assign(window, { authEvents: events })

const page = {
  light: {
    bg: "oklch(0.9795 0.0025 258.36)",
    fg: "oklch(0.1975 0.0165 258.36)",
  },
  dark: {
    bg: "oklch(0.1785 0.0085 258.36)",
    fg: "oklch(0.9275 0.0075 258.36)",
  },
}[theme]
document.head.insertAdjacentHTML(
  "beforeend",
  `<meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    @font-face { font-family: "Inter Variable"; font-weight: 100 900; src: url(/__auth-ui/inter.woff2) format("woff2"); }
    html, body { margin: 0; background: ${page.bg}; color: ${page.fg}; font-family: "Inter Variable", sans-serif; }
    input { font: inherit; }
  </style>`
)

type Challenge = { userId: string; challenge: string }

function Login() {
  const [error, setError] = useState("")
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const fail = (err: unknown) =>
    setError(String((err as { code?: string }).code ?? err))
  if (challenge)
    return (
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          const code = String(new FormData(e.currentTarget).get("code"))
          await client.verifyTwoFactor({ ...challenge, code }).catch(fail)
        }}
      >
        <input name="code" aria-label="2fa code" />
        <button>verify</button>
        <p data-testid="login-error">{error}</p>
      </form>
    )
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        const f = new FormData(e.currentTarget)
        try {
          const out = await client.signInWithPassword({
            identifier: String(f.get("identifier")),
            password: String(f.get("password")),
          })
          if (out.kind === "2fa_required") setChallenge(out)
        } catch (err) {
          fail(err)
        }
      }}
    >
      <input name="identifier" aria-label="identifier" />
      <input name="password" type="password" aria-label="password" />
      <button>sign in</button>
      <p data-testid="login-error">{error}</p>
    </form>
  )
}

function App() {
  const session = useSession()
  return (
    <main
      style={{ maxWidth: 760, margin: "0 auto", padding: "40px 16px 64px" }}
    >
      <h1
        style={{
          fontSize: 28,
          fontWeight: 700,
          letterSpacing: "-0.02em",
          margin: "0 0 24px",
        }}
      >
        Account
      </h1>
      <p data-testid="status" hidden>
        {session.status}
      </p>
      {session.status === "anonymous" && <Login />}
      {session.status === "authenticated" && (
        <button hidden onClick={() => void client.signOut()}>
          sign out
        </button>
      )}
      {session.status === "authenticated" && (
        <AccountSecurity
          linkedAccountRows={<SolanaLinkRow wallet={null} />}
          onDeleted={() => events.push("deleted")}
        />
      )}
    </main>
  )
}

const root = document.createElement("div")
document.body.append(root)
createRoot(root).render(
  <AuthProvider client={client}>
    <AuthUiProvider
      appearance={{
        theme,
        variables: { fontFamily: '"Inter Variable", sans-serif' },
      }}
    >
      <App />
    </AuthUiProvider>
  </AuthProvider>
)
