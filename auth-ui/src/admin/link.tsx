import type { AnchorHTMLAttributes, MouseEvent } from "react"

import { useRouter } from "./router.ts"

const modified = (e: MouseEvent) =>
  e.button !== 0 || e.metaKey || e.altKey || e.ctrlKey || e.shiftKey

export function Link({
  to,
  replace,
  onClick,
  ...props
}: AnchorHTMLAttributes<HTMLAnchorElement> & {
  to: string
  replace?: boolean
}) {
  const router = useRouter()
  return (
    <a
      {...props}
      href={router.href(to)}
      onClick={(e) => {
        onClick?.(e)
        if (e.defaultPrevented || modified(e) || props.target) return
        e.preventDefault()
        router.navigate(to, { replace })
      }}
    />
  )
}
