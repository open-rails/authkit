// Test helpers (not exported from the package).
import "../test/dom.ts"

import { renderHook } from "@testing-library/react"
import type { ReactNode } from "react"

import {
  createAuthClient,
  type AuthClient,
  type AuthClientOptions,
} from "../client/client.ts"
import { authResult, json } from "../client/testing.ts"
import { AuthProvider, type AuthProviderProps } from "./provider.tsx"

export const token = (claims: Record<string, unknown>) =>
  `h.${btoa(JSON.stringify({ exp: 9_999_999_999, ...claims })).replace(/=+$/, "")}.s`

// A complete AuthResult for a token carrying claims.
export const signedIn = (
  claims: Record<string, unknown>,
  fields: Parameters<typeof authResult>[1] = {}
) =>
  authResult("complete", {
    token_set: {
      access_token: token(claims),
      token_type: "Bearer",
      expires_in: 900,
      refresh_token: null,
    },
    ...fields,
  })

export const session = (claims: Record<string, unknown>) =>
  json(200, signedIn(claims))

export const noContent = () => new Response(null, { status: 204 })

export function renderWithAuth<T>(
  hook: () => T,
  fetch: typeof globalThis.fetch,
  props: Partial<AuthProviderProps> = {},
  options: AuthClientOptions = {}
): ReturnType<typeof renderHook<T, unknown>> & { client: AuthClient } {
  const client = createAuthClient({ fetch, sessionHint: false, ...options })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <AuthProvider client={client} autoStart={false} {...props}>
      {children}
    </AuthProvider>
  )
  return Object.assign(renderHook(hook, { wrapper }), { client })
}
