import type { ComponentProps } from "react"

import { AuthUiRoot } from "../../scope.tsx"
import { StepUpProvider } from "./step-up.tsx"
import { useStepUpController } from "./step-up-context.ts"

// Standalone panels get their own step-up dialog; inside a StepUpProvider
// they share its one.
export function PanelRoot({ className, ...props }: ComponentProps<"div">) {
  const root = (
    <AuthUiRoot
      className={["grid gap-6", className].filter(Boolean).join(" ")}
      {...props}
    />
  )
  return useStepUpController() ? root : <StepUpProvider>{root}</StepUpProvider>
}
