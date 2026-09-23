/* eslint-disable react-refresh/only-export-components */
// Host page for sign-in.spec.ts: the styled components from the packaged dist/.
import { useState } from "react"
import { createRoot } from "react-dom/client"

import { createAuthClient, readLinkFragment } from "../../dist/client.js"
import {
  AuthCallback,
  AuthUiProvider,
  ResetPasswordForm,
  SignInDialog,
} from "../../dist/index.js"
import { AuthProvider, useSession, useUser } from "../../dist/react.js"
import {
  SolanaSignInButton,
  SolanaWalletError,
  type SolanaSigner,
} from "../../dist/solana.js"

const params = new URLSearchParams(location.search)
const theme = params.get("theme") === "dark" ? "dark" : "light"
const page = params.get("page") ?? "home"
document.documentElement.style.colorScheme = theme
document.body.style.margin = "0"
document.body.style.background = theme === "dark" ? "#15171c" : "#f6f7f9"
// Pinned so screenshots match between local and CI (both Ubuntu 24.04).
const font = '"Liberation Sans", Arial, sans-serif'
document.body.style.fontFamily = font

const client = createAuthClient()
const signedIn: (string | null)[] = []
Object.assign(window, { signedIn, authClient: client })

// solana.spec.ts sets window.walletAddress and exposes walletSign (an Ed25519
// key held by the test), standing in for a lazily loaded wallet stack.
type TestWallet = {
  walletAddress?: string
  walletSign?: (address: string, message: string) => Promise<string>
}
async function acquireSigner(): Promise<SolanaSigner> {
  const w = window as TestWallet
  const address = w.walletAddress
  const sign = w.walletSign
  if (!address || !sign) throw new SolanaWalletError("not_connected")
  return {
    publicKey: address,
    signMessage: async (m) => {
      const sig = await sign(address, btoa(String.fromCharCode(...m)))
      return Uint8Array.from(atob(sig), (c) => c.charCodeAt(0))
    },
  }
}

function Backdrop() {
  const tone = theme === "dark" ? "#23262d" : "#e4e6ea"
  return (
    <div aria-hidden="true" style={{ padding: 24, display: "grid", gap: 16 }}>
      <div
        style={{ height: 40, width: 180, borderRadius: 8, background: tone }}
      />
      <div
        style={{
          display: "grid",
          gap: 16,
          gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
        }}
      >
        {Array.from({ length: 8 }, (_, i) => (
          <div
            key={i}
            style={{ height: 220, borderRadius: 12, background: tone }}
          />
        ))}
      </div>
    </div>
  )
}

function Home() {
  const session = useSession()
  const { user } = useUser()
  const [open, setOpen] = useState(params.get("open") === "1")
  const tab = params.get("tab") === "register" ? "register" : "login"
  return (
    <main>
      <header style={{ display: "flex", gap: 12, padding: 12 }}>
        <span data-testid="status">{session.status}</span>
        <span data-testid="email">{user?.email ?? ""}</span>
        <button onClick={() => setOpen(true)}>open sign in</button>
        <button onClick={() => void client.signOut()}>sign out</button>
      </header>
      <Backdrop />
      <SignInDialog
        open={open}
        onOpenChange={setOpen}
        initialTab={tab}
        termsUrl="/terms"
        privacyUrl="/privacy"
        footer="Welcome back!"
        onSignedIn={({ returnTo }) => signedIn.push(returnTo ?? null)}
        renderSolana={({ mode, onOutcome, disabled }) => (
          <SolanaSignInButton
            acquireSigner={acquireSigner}
            mode={mode}
            onOutcome={onOutcome}
            disabled={disabled}
          />
        )}
      />
    </main>
  )
}

function Reset() {
  const [token] = useState(() => readLinkFragment(location.hash)?.token)
  const [done, setDone] = useState(false)
  if (done) return <p data-testid="reset-done">done</p>
  return (
    <div style={{ maxWidth: 420, margin: "48px auto", padding: 16 }}>
      <ResetPasswordForm token={token} onDone={() => setDone(true)} />
    </div>
  )
}

function Callback() {
  const [went, setWent] = useState<string | null>(null)
  if (went !== null) return <p data-testid="navigated">{went}</p>
  return <AuthCallback navigate={setWent} />
}

const root = document.createElement("div")
document.body.append(root)
createRoot(root).render(
  <AuthProvider client={client}>
    <AuthUiProvider appearance={{ theme, variables: { fontFamily: font } }}>
      {page === "reset" ? (
        <Reset />
      ) : page === "callback" ? (
        <Callback />
      ) : (
        <Home />
      )}
    </AuthUiProvider>
  </AuthProvider>
)
