import {
  ComputerIcon,
  Logout03Icon,
  SmartPhone01Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useState } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useSessions, type SessionEntry } from "../../react/account.ts"
import { Badge } from "../../ui/badge.tsx"
import { Button } from "../../ui/button.tsx"
import { Checkbox } from "../../ui/checkbox.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { parseUserAgent, relativeTime } from "./lib.ts"
import { PanelRoot } from "./panel-root.tsx"
import { ConfirmDialog, ErrorNotice, PanelCard } from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface SessionsPanelProps {
  className?: string
}

/** Signed-in devices, with batch sign-out. */
export function SessionsPanel({ className }: SessionsPanelProps) {
  return (
    <PanelRoot className={className}>
      <SessionsCard />
    </PanelRoot>
  )
}

function SessionsCard() {
  const { t } = useMessages()
  const s = useSessions({ guard: useStepUpGuard() })
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [everywhere, setEverywhere] = useState(false)
  const sessions = [...(s.sessions ?? [])].sort(
    (a, b) =>
      Number(b.current) - Number(a.current) ||
      b.last_used_at.localeCompare(a.last_used_at)
  )
  const others = sessions.filter((x) => !x.current)
  const chosen = others.filter((x) => selected.has(x.session_id))

  const revoke = async (ids: string[]) => {
    await s.revoke(ids)
    setSelected((prev) => {
      const next = new Set(prev)
      for (const id of ids) next.delete(id)
      return next
    })
  }

  return (
    <PanelCard
      icon={ComputerIcon}
      title={t("account.sessions.title")}
      description={t("account.sessions.description")}
    >
      {s.loading && !s.sessions && (
        <div className="flex justify-center px-6 py-6">
          <Spinner />
        </div>
      )}
      {s.sessions && (
        <ul aria-label={t("account.sessions.title")} className="divide-y">
          {sessions.map((x) => (
            <SessionRow
              key={x.session_id}
              session={x}
              checked={selected.has(x.session_id)}
              busy={s.busy}
              onCheckedChange={(on) =>
                setSelected((prev) => {
                  const next = new Set(prev)
                  if (on) next.add(x.session_id)
                  else next.delete(x.session_id)
                  return next
                })
              }
              onRevoke={() => void revoke([x.session_id])}
            />
          ))}
        </ul>
      )}
      {s.sessions && others.length === 0 && (
        <p className="px-5 py-4 text-sm text-muted-foreground sm:px-6">
          {t("account.sessions.noOthers")}
        </p>
      )}
      {s.error && (
        <div className="px-5 py-4 sm:px-6">
          <ErrorNotice error={s.error} />
        </div>
      )}
      {s.sessions && (
        <div className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:flex-wrap sm:px-6">
          {chosen.length > 0 ? (
            <Button
              variant="outline"
              disabled={s.busy}
              onClick={() => void revoke(chosen.map((x) => x.session_id))}
            >
              {s.busy && <Spinner />}
              {t("account.sessions.revokeSelected", { count: chosen.length })}
            </Button>
          ) : (
            others.length > 0 && (
              <Button
                variant="outline"
                disabled={s.busy}
                onClick={() => void revoke(others.map((x) => x.session_id))}
              >
                {s.busy && <Spinner />}
                {t("account.sessions.revokeAll")}
              </Button>
            )
          )}
          <Button
            variant="ghost"
            className="text-destructive hover:text-destructive sm:ml-auto"
            disabled={s.busy}
            onClick={() => setEverywhere(true)}
          >
            <HugeiconsIcon icon={Logout03Icon} strokeWidth={2} />
            {t("account.sessions.revokeEverywhere")}
          </Button>
        </div>
      )}
      <ConfirmDialog
        open={everywhere}
        onOpenChange={setEverywhere}
        title={t("account.sessions.revokeEverywhereTitle")}
        description={t("account.sessions.revokeEverywhereDescription")}
        confirmLabel={t("account.sessions.revokeEverywhere")}
        destructive
        onConfirm={() => {
          setEverywhere(false)
          void s.revokeAll()
        }}
      />
    </PanelCard>
  )
}

function SessionRow({
  session,
  checked,
  busy,
  onCheckedChange,
  onRevoke,
}: {
  session: SessionEntry
  checked: boolean
  busy: boolean
  onCheckedChange: (checked: boolean) => void
  onRevoke: () => void
}) {
  const { t } = useMessages()
  const device = parseUserAgent(session.ua)
  const name =
    device.browser && device.os
      ? t("account.sessions.device", { browser: device.browser, os: device.os })
      : (device.browser ?? device.os ?? t("account.sessions.unknownDevice"))
  const details = [
    session.current
      ? null
      : t("account.sessions.lastActive", {
          time: relativeTime(session.last_used_at),
        }),
    t("account.sessions.signedIn", { time: relativeTime(session.created_at) }),
    session.ip,
  ].filter(Boolean)

  return (
    <li className="flex items-center gap-3 px-5 py-3.5 sm:gap-4 sm:px-6">
      <span className="flex w-4 shrink-0 justify-center">
        {!session.current && (
          <Checkbox
            checked={checked}
            disabled={busy}
            onCheckedChange={(v) => onCheckedChange(v === true)}
            aria-label={t("account.sessions.selectSession", { device: name })}
          />
        )}
      </span>
      <span
        aria-hidden
        className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground"
      >
        <HugeiconsIcon
          icon={device.mobile ? SmartPhone01Icon : ComputerIcon}
          strokeWidth={1.75}
          className="size-[18px]"
        />
      </span>
      <div className="grid min-w-0 flex-1 gap-0.5">
        <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
          <span className="truncate">{name}</span>
          {session.current && (
            <Badge variant="secondary">{t("account.sessions.current")}</Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground sm:text-sm">
          {details.join(" · ")}
        </p>
      </div>
      {!session.current && (
        <Button
          variant="ghost"
          size="sm"
          disabled={busy}
          aria-label={`${t("account.sessions.revoke")}: ${name}`}
          onClick={onRevoke}
        >
          {t("account.sessions.revoke")}
        </Button>
      )}
    </li>
  )
}
