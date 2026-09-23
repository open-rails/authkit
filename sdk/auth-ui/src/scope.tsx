import type { ComponentProps } from "react"

import { cn } from "./lib/utils.ts"
import { useScopeProps } from "./scope-context.ts"

/** Every in-page auth-ui surface renders inside one of these. */
export function AuthUiRoot({
  className,
  style,
  ...props
}: ComponentProps<"div">) {
  const scope = useScopeProps()
  return (
    <div
      data-authui-theme={scope["data-authui-theme"]}
      className={cn(scope.className, className)}
      style={{ ...scope.style, ...style }}
      {...props}
    />
  )
}
