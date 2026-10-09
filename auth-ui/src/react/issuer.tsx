import { useEffect, useLayoutEffect, type ReactNode } from "react"

import type { IssuerClient } from "../client/issuer.ts"
import { IssuerContext } from "./issuerContext.ts"

const useStartEffect =
  typeof window === "undefined" ? useEffect : useLayoutEffect

export type IssuerAuthProviderProps = {
  client: IssuerClient
  // Call client.start() while mounted. Default true.
  autoStart?: boolean
  children?: ReactNode
}

// Provides an external issuer's session (createIssuerClient) to the tree.
export function IssuerAuthProvider({
  client,
  autoStart = true,
  children,
}: IssuerAuthProviderProps) {
  useStartEffect(
    () => (autoStart ? client.start() : undefined),
    [client, autoStart]
  )
  return (
    <IssuerContext.Provider value={client}>{children}</IssuerContext.Provider>
  )
}
