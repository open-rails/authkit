import { useEffect, useRef, useState, type ReactNode } from "react"

import type { AuthClient, AuthSession } from "../client/client.ts"
import {
  AuthContext,
  createAuthContextValue,
  sessionIdentity,
} from "./context.ts"

export type AuthProviderProps = {
  client: AuthClient
  // Fires on sign-in, sign-out, expiry and user switch (not silent refresh):
  // the host's hook to reset its query cache and stores.
  onSessionChange?: (session: AuthSession, previous: AuthSession) => void
  // Call client.start() while mounted. Default true.
  autoStart?: boolean
  children?: ReactNode
}

export function AuthProvider({
  client,
  onSessionChange,
  autoStart = true,
  children,
}: AuthProviderProps) {
  const [value, setValue] = useState(() => createAuthContextValue(client))
  if (value.client !== client) setValue(createAuthContextValue(client))

  const onChange = useRef(onSessionChange)
  useEffect(() => {
    onChange.current = onSessionChange
  })

  useEffect(() => {
    let previous = client.getSnapshot()
    return client.subscribe(() => {
      const next = client.getSnapshot()
      if (sessionIdentity(next) === sessionIdentity(previous)) {
        previous = next
        return
      }
      const before = previous
      previous = next
      onChange.current?.(next, before)
    })
  }, [client])

  useEffect(() => (autoStart ? client.start() : undefined), [client, autoStart])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
