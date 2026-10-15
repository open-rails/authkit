import type { ComponentProps } from "react"
import { cn } from "cn"

import { AuthUiRoot } from "../../scope.tsx"
import { StepUpProvider } from "./step-up.tsx"
import { useStepUpController } from "./step-up-context.ts"

// Standalone panels get their own step-up dialog; inside a StepUpProvider
// they share its one.
export function PanelRoot({ className, ...props }: ComponentProps<"div">) {
  const root = (
    <AuthUiRoot>
      <div className={cn("grid gap-6", className)} {...props} />
    </AuthUiRoot>
  )
  return useStepUpController() ? root : <StepUpProvider>{root}</StepUpProvider>
}
