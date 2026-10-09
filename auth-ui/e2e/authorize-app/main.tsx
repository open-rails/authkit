// The issuer's authorize page (Frontend.AuthorizePath) for issuer.spec.ts,
// from the packaged dist/.
import { createRoot } from "react-dom/client"

import { createAuthClient } from "../../dist/client.js"
import { AuthUiProvider, OAuthAuthorize } from "../../dist/index.js"
import { AuthProvider } from "../../dist/react.js"

const client = createAuthClient()
const root = document.createElement("div")
document.body.append(root)
createRoot(root).render(
  <AuthProvider client={client}>
    <AuthUiProvider>
      <OAuthAuthorize />
    </AuthUiProvider>
  </AuthProvider>
)
