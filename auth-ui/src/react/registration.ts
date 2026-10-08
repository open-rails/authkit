import {
  registrationAvailable,
  registrationMode,
  type RegistrationMode,
} from "../client/registration.ts"
import { useCapabilities } from "./context.ts"

export type RegistrationState = {
  // null until /capabilities answers.
  mode: RegistrationMode | null
  // Whether to offer sign-up; false while loading or after an error.
  available: boolean
  loading: boolean
}

// Gate sign-up UI (links, tabs, CTAs) on AuthKit's registration policy.
// Pass the visitor's invitation code when the host has one.
export function useRegistration(inviteCode?: string): RegistrationState {
  const { capabilities, loading } = useCapabilities()
  return {
    mode: registrationMode(capabilities),
    available: registrationAvailable(capabilities, inviteCode),
    loading,
  }
}
