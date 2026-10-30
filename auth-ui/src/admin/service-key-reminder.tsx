import { Notice } from "../components/account/shared.tsx"
import { Button } from "../ui/button.tsx"
import { useAdminMessages } from "./i18n.ts"

/** A general reminder, without inferring which secrets a person possesses. */
export function ServiceKeyReminder({
  name,
  onReview,
  onDismiss,
}: {
  name: string
  onReview?: () => void
  onDismiss: () => void
}) {
  const { t } = useAdminMessages()
  return (
    <Notice
      tone="warning"
      action={
        <div className="flex flex-wrap gap-2">
          {onReview && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={onReview}
            >
              {t("offboarding.review")}
            </Button>
          )}
          <Button type="button" size="sm" variant="ghost" onClick={onDismiss}>
            {t("offboarding.done")}
          </Button>
        </div>
      }
    >
      {t("offboarding.reminder", { name })}
    </Notice>
  )
}
