// Host page for solana.spec.ts: the packaged client and solana entries.
import { createAuthClient } from "../../dist/client.js"
import { createSolanaAuth } from "../../dist/solana.js"

const auth = createAuthClient()
Object.assign(window, { auth, solana: createSolanaAuth(auth) })
