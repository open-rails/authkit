import { createContext, useContext } from "react"

import type { StepUpController } from "../../react/useStepUp.ts"
import { unguarded, type Guard } from "../../react/task.ts"

export const StepUpContext = createContext<StepUpController | null>(null)

/** The nearest `StepUpProvider`'s controller, or null outside one. */
export function useStepUpController(): StepUpController | null {
  return useContext(StepUpContext)
}

/** Runs sensitive actions through the nearest `StepUpProvider`'s dialog. */
export function useStepUpGuard(): Guard {
  return useContext(StepUpContext)?.guard ?? unguarded
}
