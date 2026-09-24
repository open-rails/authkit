// Test helpers (not exported from the package).
import "../test/dom.ts"

import { renderHook } from "@testing-library/react"
import type { ReactNode } from "react"

import { createAuthClient, type AuthClient } from "../client/client.ts"
import { json } from "../client/testing.ts"
import { AuthProvider, type AuthProviderProps } from "./provider.tsx"

export const token = (claims: Record<string, unknown>) =>
  `h.${btoa(JSON.stringify({ exp: 9_999_999_999, ...claims })).replace(/=+$/, "")}.s`

export const session = (claims: Record<string, unknown>) =>
  json(200, { access_token: token(claims), token_type: "Bearer" })

export const noContent = () => new Response(null, { status: 204 })

export function renderWithAuth<T>(
  hook: () => T,
  fetch: typeof globalThis.fetch,
  props: Partial<AuthProviderProps> = {}
): ReturnType<typeof renderHook<T, unknown>> & { client: AuthClient } {
  const client = createAuthClient({ fetch })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <AuthProvider client={client} autoStart={false} {...props}>
      {children}
    </AuthProvider>
  )
  return Object.assign(renderHook(hook, { wrapper }), { client })
}
