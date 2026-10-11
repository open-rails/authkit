import { createContext, useContext } from "react"

import type { Guard } from "../react/task.ts"
import type { AdminClient } from "./client.ts"

export type AdminContextValue = { client: AdminClient; guard?: Guard }

export const AdminContext = createContext<AdminContextValue | null>(null)

export function useAdmin(): AdminContextValue {
  const value = useContext(AdminContext)
  if (!value) throw new Error("auth-ui admin: rendered outside its root")
  return value
}
