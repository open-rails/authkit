import { createContext, useContext } from "react"

import type { Guard } from "../react/task.ts"
import type { AdminClient } from "./client.ts"

export type AdminContextValue = {
  client: AdminClient
  guard?: Guard
  /** The account directory being administered; never the source session. */
  tenantId?: string
  /** Isolates cached reads and resumable writes by mounted authority/target. */
  scopeKey: string
}

export const AdminContext = createContext<AdminContextValue | null>(null)

export function useAdmin(): AdminContextValue {
  const value = useContext(AdminContext)
  if (!value) throw new Error("auth-ui admin: rendered outside its root")
  return value
}
