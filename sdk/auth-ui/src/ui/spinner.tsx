import { HugeiconsIcon } from "@hugeicons/react"
import { Loading02Icon } from "@hugeicons/core-free-icons"
import { useMessages } from "../i18n/context.ts"
import { cn } from "../lib/utils.ts"

function Spinner({
  className,
  ...props
}: Omit<React.ComponentProps<typeof HugeiconsIcon>, "icon">) {
  const { t } = useMessages()
  return (
    <HugeiconsIcon
      icon={Loading02Icon}
      data-slot="spinner"
      role="status"
      aria-label={t("common.loading")}
      className={cn("size-4 animate-spin", className)}
      {...props}
    />
  )
}

export { Spinner }
