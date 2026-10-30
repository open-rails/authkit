import { useCallback, useId, useState, type ReactNode } from "react"

import type { GroupRole, UserEntry } from "../client/generated/wire.ts"
import { Notice } from "../components/account/shared.tsx"
import { Badge } from "../ui/badge.tsx"
import { Button } from "../ui/button.tsx"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog.tsx"
import { Input } from "../ui/input.tsx"
import { Checkbox } from "../ui/checkbox.tsx"
import type { UsersPermissions } from "./access.ts"
import type { BanInput, SessionEventKind, UserUpdate } from "./client.ts"
import { useAdmin } from "./context.ts"
import { browserAndOS, dateTime, languageName } from "./format.ts"
import { useAdminMessages, type AdminMessageKey } from "./i18n.ts"
import { Link } from "./link.tsx"
import { useLoad } from "./load.ts"
import { usePages } from "./pages.ts"
import {
  Body,
  ConfirmDialog,
  CopyButton,
  Empty,
  ErrorText,
  FormField,
  LoadMore,
  Loading,
  Section,
  Select,
  Table,
  Td,
  Th,
  TypedConfirm,
} from "./parts.tsx"
import { roleTitle } from "./roles-lib.ts"
import { useSearchParams } from "./router.ts"
import type { Host } from "./users.tsx"

type Method = keyof typeof METHODS
const END_REASONS = {
  user_revoke: 1,
  user_revoke_all: 1,
  admin_revoke: 1,
  admin_revoke_all: 1,
  password_change: 1,
  admin_set_password: 1,
  contact_change: 1,
  contact_proven: 1,
  mfa_reset: 1,
  banned: 1,
  soft_deleted: 1,
  evicted: 1,
  refresh_reuse_detected: 1,
}
type EndReason = keyof typeof END_REASONS

/** "Chrome on macOS" for a known user agent; the full string stays in the cell's title. */
function Device({ ua }: { ua: string | null | undefined }) {
  const { t } = useAdminMessages()
  const known = browserAndOS(ua)
  return <>{known ? t("users.deviceOn", known) : (ua ?? "—")}</>
}
import { BanLine, UserBadges } from "./user-parts.tsx"
import { directoryRole, restorableUntil, userName } from "./users-lib.ts"
import { useWarnings } from "./warnings.tsx"
import { useActions } from "./write.ts"
import { losesRoleAccess } from "./offboarding-lib.ts"
import { ServiceKeyReminder } from "./service-key-reminder.tsx"

// Sign-in methods and sign-out reasons the server records; others show as sent.
const METHODS = {
  password_login: 1,
  passkey_login: 1,
  oidc_login: 1,
  solana_login: 1,
  registration: 1,
  email_verification: 1,
  phone_verification: 1,
  refresh_mfa: 1,
  passwordless_email: 1,
  passwordless_sms: 1,
}

type Open =
  "edit" | "ban" | "delete" | "restore" | "signOut" | { role: string } | null

// One account: its standing and the acts the caller's permissions allow.
export function UserPage({
  id,
  access,
  roles,
  roleCatalog,
  host,
}: {
  id: string
  access: UsersPermissions
  roles: string[]
  roleCatalog: readonly GroupRole[]
  host: Host
}) {
  const { t } = useAdminMessages()
  const { client, tenantId, language } = useAdmin()
  const loaded = useLoad(`user:${id}`, (s) => client.getUser(id, s))
  const sessions = useLoad(`sessions:${id}`, (s) =>
    client.listUserSessions(id, s)
  )
  const [open, setOpen] = useState<Open>(null)
  const [status, setStatus] = useState("")
  const [reviewServiceKeys, setReviewServiceKeys] = useState(false)
  const [changes, setChanges] = useState(0)
  const user = loaded.data
  const role = user ? directoryRole(user, tenantId) : null
  const group = tenantId ?? "root"
  const name = user ? userName(user) : id
  const actions = useActions(
    `authkit.user:${id}`,
    {
      update: (d: UserUpdate) => client.updateUser(id, d),
      ban: (d: BanInput) => client.banUser(id, d),
      unban: () => client.unbanUser(id),
      delete: () => client.deleteUser(id),
      restore: () => client.restoreUser(id),
      signOut: () => client.revokeUserSessions(id),
      role: (d: { role: string; previousRole: string | null }) =>
        d.role
          ? client.setMemberRole(group, id, d.role)
          : client.removeMember(group, id),
    },
    (kind, _result, data) => {
      const change = data as
        { role?: string; previousRole?: string | null } | undefined
      setReviewServiceKeys(
        kind === "role" &&
          losesRoleAccess(change?.previousRole, change?.role, roleCatalog)
      )
      const role = (data as { role?: string } | undefined)?.role
      setStatus(
        kind === "role"
          ? role
            ? t("users.roleChanged", { name, role: roleTitle(role) })
            : t(tenantId ? "users.tenantRoleRemoved" : "users.roleRemoved", {
                name,
              })
          : t(`users.done.${String(kind)}` as AdminMessageKey, { name })
      )
      setOpen(null)
      loaded.reload()
      sessions.reload()
      setChanges((n) => n + 1)
    }
  )
  const show = (next: Open) => {
    actions.clear()
    setStatus("")
    setOpen(next)
  }
  const ban = useWarnings(host.confirmWarnings, user, "ban", open === "ban")
  const del = useWarnings(
    host.confirmWarnings,
    user,
    "delete",
    open === "delete"
  )

  const back = (
    <Link
      to=""
      className="justify-self-start text-sm text-muted-foreground hover:text-foreground"
    >
      ← {t("users.back")}
    </Link>
  )
  if (loaded.loading)
    return (
      <div className="grid gap-6">
        {back}
        <Section title={t("users.title")}>
          <Loading />
        </Section>
      </div>
    )
  if (!user)
    return (
      <div className="grid gap-6">
        {back}
        {loaded.error?.status === 404 ? (
          <Section title={t("users.title")}>
            <Empty>{t("users.notFound")}</Empty>
          </Section>
        ) : (
          <ErrorText error={loaded.error} onRetry={loaded.reload} />
        )}
      </div>
    )

  const deleted = Boolean(user.deleted_at)
  const buttons: ReactNode[] = []
  if (deleted && access.users.delete)
    buttons.push(
      <Button key="restore" size="sm" onClick={() => show("restore")}>
        {t("users.restore")}
      </Button>
    )
  if (!deleted && access.users.ban)
    buttons.push(
      user.ban ? (
        <Button
          key="unban"
          variant="outline"
          size="sm"
          disabled={actions.busy}
          onClick={() => {
            show(null)
            void actions.run("unban", undefined)
          }}
        >
          {t("users.unban")}
        </Button>
      ) : (
        <Button
          key="ban"
          variant="destructive"
          size="sm"
          onClick={() => show("ban")}
        >
          {t("users.ban")}
        </Button>
      )
    )
  if (!deleted && access.users.delete)
    buttons.push(
      <Button
        key="delete"
        variant="outline"
        size="sm"
        className="text-destructive"
        onClick={() => show("delete")}
      >
        {t("users.delete")}
      </Button>
    )
  const pendingRole = typeof open === "object" && open ? open.role : null

  return (
    <div className="grid gap-6">
      {back}
      <Section
        title={
          <span
            className={
              deleted ? "text-muted-foreground line-through" : undefined
            }
          >
            {name}
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-x-1 font-mono text-xs">
            {user.id}
            <CopyButton value={user.id} label={t("users.id")} />
          </span>
        }
        actions={buttons.length > 0 && buttons}
      >
        <Body>
          <UserBadges user={user} role={role} />
          <BanLine user={user} />
          {user.deleted_at && (
            <p className="text-sm text-muted-foreground">
              {t("users.deletedOn", {
                date: dateTime(user.deleted_at, language),
                until: dateTime(restorableUntil(user.deleted_at), language),
              })}
            </p>
          )}
          {!open && <ErrorText error={actions.error} />}
          {status && !actions.error && <Notice tone="success">{status}</Notice>}
        </Body>
      </Section>

      {reviewServiceKeys && (
        <ServiceKeyReminder
          name={name}
          onReview={
            host.onReviewServiceKeys &&
            (() => host.onReviewServiceKeys?.({ group, userId: id }))
          }
          onDismiss={() => setReviewServiceKeys(false)}
        />
      )}

      <Details
        user={user}
        onEdit={
          access.users.manage && !deleted ? () => show("edit") : undefined
        }
      />
      {access.roles.read && (
        <DirectoryRole
          key={role ?? ""}
          current={role ?? ""}
          tenant={Boolean(tenantId)}
          roles={roles}
          canManage={access.roles.manage && !deleted}
          busy={actions.busy}
          onSave={(role) => show({ role })}
        />
      )}
      {host.userPanels && (
        <div className="grid gap-6" data-slot="user-panels">
          {host.userPanels(user)}
        </div>
      )}
      <Section
        title={t("users.sessions")}
        description={t("users.sessionsDescription")}
        actions={
          access.users.manage &&
          !deleted && (
            <Button
              variant="outline"
              size="sm"
              disabled={actions.busy}
              onClick={() => show("signOut")}
            >
              {t("users.signOutAll")}
            </Button>
          )
        }
      >
        {sessions.loading ? (
          <Loading rows={2} />
        ) : sessions.error ? (
          <Body>
            <ErrorText error={sessions.error} onRetry={sessions.reload} />
          </Body>
        ) : !sessions.data?.length ? (
          <Empty>{t("users.noSessions")}</Empty>
        ) : (
          <Table aria-label={t("users.sessions")}>
            <thead>
              <tr>
                <Th>{t("users.started")}</Th>
                <Th>{t("users.lastUsed")}</Th>
                <Th>{t("users.ip")}</Th>
                <Th>{t("users.device")}</Th>
              </tr>
            </thead>
            <tbody>
              {sessions.data.map((s) => (
                <tr key={s.id}>
                  <Td className="whitespace-nowrap">
                    {dateTime(s.created_at, language)}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {dateTime(s.last_used_at, language)}
                  </Td>
                  <Td className="font-mono text-xs">{s.ip ?? "—"}</Td>
                  <Td className="max-w-72 truncate" title={s.user_agent ?? ""}>
                    <Device ua={s.user_agent} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      <History id={id} changes={changes} />

      <EditDialog
        user={user}
        languages={host.languages}
        open={open === "edit"}
        onOpenChange={(o) => !o && setOpen(null)}
        busy={actions.busy}
        error={actions.error}
        onSave={(update) => void actions.run("update", update)}
      />
      <BanDialog
        name={name}
        open={open === "ban"}
        onOpenChange={(o) => !o && setOpen(null)}
        busy={actions.busy}
        error={actions.error}
        warnings={ban}
        onBan={(input) => void actions.run("ban", input)}
      />
      <TypedConfirm
        open={open === "delete"}
        onOpenChange={(o) => !o && setOpen(null)}
        title={t("users.deleteTitle", { name })}
        description={t("users.deleteDescription")}
        word={name}
        confirmLabel={t("users.delete")}
        busy={actions.busy}
        disabled={del.pending}
        onConfirm={() => void actions.run("delete", undefined)}
      >
        {del.node}
        <ErrorText error={actions.error} />
      </TypedConfirm>
      <TypedConfirm
        open={pendingRole !== null}
        onOpenChange={(o) => !o && setOpen(null)}
        title={t(
          tenantId ? "users.tenantRoleConfirmTitle" : "users.roleConfirmTitle",
          { name }
        )}
        description={t("users.roleConfirmDescription", {
          from: role ? roleTitle(role) : t("users.roleNone"),
          to: pendingRole ? roleTitle(pendingRole) : t("users.roleNone"),
        })}
        word={name}
        confirmLabel={t("users.roleSave")}
        busy={actions.busy}
        onConfirm={() =>
          pendingRole !== null &&
          void actions.run("role", { role: pendingRole, previousRole: role })
        }
      >
        {pendingRole !== null &&
          losesRoleAccess(role, pendingRole, roleCatalog) && (
            <p className="text-sm text-muted-foreground">
              {t("offboarding.reminder", { name })}
            </p>
          )}
        <ErrorText error={actions.error} />
      </TypedConfirm>
      <ConfirmDialog
        open={open === "restore"}
        onOpenChange={(o) => !o && setOpen(null)}
        title={t("users.restoreTitle", { name })}
        description={t("users.restoreDescription")}
        confirmLabel={t("users.restore")}
        busy={actions.busy}
        onConfirm={() => void actions.run("restore", undefined)}
      >
        <ErrorText error={actions.error} />
      </ConfirmDialog>
      <ConfirmDialog
        open={open === "signOut"}
        onOpenChange={(o) => !o && setOpen(null)}
        title={t("users.signOutTitle", { name })}
        description={t("users.signOutDescription")}
        confirmLabel={t("users.signOutAll")}
        busy={actions.busy}
        destructive
        onConfirm={() => void actions.run("signOut", undefined)}
      >
        <ErrorText error={actions.error} />
      </ConfirmDialog>
    </div>
  )
}

function Details({ user, onEdit }: { user: UserEntry; onEdit?: () => void }) {
  const { t } = useAdminMessages()
  const { language } = useAdmin()
  const verified = (yes: boolean) => (
    <Badge variant="outline" className={yes ? "text-success" : undefined}>
      {yes ? t("users.verified") : t("users.unverified")}
    </Badge>
  )
  return (
    <Section
      title={t("users.details")}
      actions={
        onEdit && (
          <Button variant="outline" size="sm" onClick={onEdit}>
            {t("users.edit")}
          </Button>
        )
      }
    >
      <dl className="grid gap-x-6 gap-y-1 px-5 py-4 text-sm sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-y-3 sm:px-6">
        <Row label={t("users.username")} value={user.username} />
        <Row
          label={t("users.email")}
          value={user.email}
          copy
          extra={user.email && verified(user.email_verified)}
        />
        <Row
          label={t("users.phone")}
          value={user.phone_number}
          copy
          extra={user.phone_number && verified(user.phone_verified)}
        />
        <Row
          label={t("users.language")}
          value={languageName(user.preferred_language, language)}
        />
        <Row
          label={t("users.joined")}
          value={dateTime(user.created_at, language)}
        />
        <Row
          label={t("users.updated")}
          value={dateTime(user.updated_at, language)}
        />
        <Row
          label={t("users.lastLogin")}
          value={dateTime(user.last_login, language) || t("common.never")}
        />
      </dl>
    </Section>
  )
}

function Row({
  label,
  value,
  copy,
  extra,
}: {
  label: string
  value: string | null
  copy?: boolean
  extra?: ReactNode
}) {
  return (
    <>
      <dt className="pt-2 text-muted-foreground first:pt-0 sm:pt-0">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1.5">
        <span className="truncate">{value || "—"}</span>
        {copy && value && <CopyButton value={value} label={label} />}
        {extra}
      </dd>
    </>
  )
}

function DirectoryRole({
  current,
  tenant,
  roles,
  canManage,
  busy,
  onSave,
}: {
  current: string
  tenant: boolean
  roles: string[]
  canManage: boolean
  busy: boolean
  onSave: (role: string) => void
}) {
  const { t } = useAdminMessages()
  const [value, setValue] = useState(current)
  const options = [...new Set([...(current ? [current] : []), ...roles])]
  return (
    <Section
      title={t(tenant ? "users.tenantRoleTitle" : "users.roleTitle")}
      description={t(
        tenant ? "users.tenantRoleDescription" : "users.roleDescription"
      )}
    >
      <Body>
        <form
          className="flex flex-wrap items-center gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            onSave(value)
          }}
        >
          <Select
            aria-label={t(tenant ? "users.tenantRoleTitle" : "users.role")}
            className="min-w-48"
            value={value}
            disabled={!canManage}
            onChange={(e) => setValue(e.target.value)}
          >
            <option value="">{t("users.roleNone")}</option>
            {options.map((r) => (
              <option key={r} value={r}>
                {roleTitle(r)}
              </option>
            ))}
          </Select>
          {canManage && (
            <Button type="submit" disabled={busy || value === current}>
              {t("users.roleSave")}
            </Button>
          )}
        </form>
        {!canManage && (
          <p className="text-xs text-muted-foreground">
            {t("common.readOnly")}
          </p>
        )}
      </Body>
    </Section>
  )
}

const KINDS: readonly SessionEventKind[] = [
  "session_created",
  "session_failed",
  "session_revoked",
  "account_sessions_revoked",
  "password_changed",
  "password_recovery",
]

function History({ id, changes }: { id: string; changes: number }) {
  const { t } = useAdminMessages()
  const { client, language } = useAdmin()
  const filterId = useId()
  const [search, setSearch] = useSearchParams()
  const raw = search.get("kind") ?? ""
  const kind = (KINDS as readonly string[]).includes(raw)
    ? (raw as SessionEventKind)
    : ""
  const page = useCallback(
    (cursor?: string, signal?: AbortSignal) =>
      client.listUserSessionEvents(
        id,
        { cursor, kind: kind ? [kind] : undefined },
        signal
      ),
    [client, id, kind]
  )
  const list = usePages(`history:${id}:${kind}:${changes}`, page)
  return (
    <Section
      title={t("users.history")}
      description={t("users.historyDescription")}
      actions={
        <div className="flex items-center gap-2">
          <label htmlFor={filterId} className="text-sm text-muted-foreground">
            {t("users.event")}
          </label>
          <Select
            id={filterId}
            value={kind}
            onChange={(e) => {
              const next = new URLSearchParams(search)
              if (e.target.value) next.set("kind", e.target.value)
              else next.delete("kind")
              setSearch(next)
            }}
          >
            <option value="">{t("users.allEvents")}</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`users.kinds.${k}`)}
              </option>
            ))}
          </Select>
        </div>
      }
    >
      {list.loading ? (
        <Loading rows={3} />
      ) : list.error && !list.items ? (
        <Body>
          <ErrorText error={list.error} onRetry={list.reload} />
        </Body>
      ) : !list.items?.length ? (
        <Empty>{kind ? t("users.noEventsOfKind") : t("users.noHistory")}</Empty>
      ) : (
        <>
          <Table aria-label={t("users.history")}>
            <thead>
              <tr>
                <Th>{t("users.when")}</Th>
                <Th>{t("users.event")}</Th>
                <Th>{t("users.method")}</Th>
                <Th>{t("users.ip")}</Th>
                <Th>{t("users.device")}</Th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((e, i) => (
                <tr key={`${e.occurred_at}:${e.session_id ?? ""}:${i}`}>
                  <Td className="whitespace-nowrap">
                    {dateTime(e.occurred_at, language)}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {t(`users.kinds.${e.kind}`)}
                    {e.reason && e.reason !== "logout" && (
                      <span className="text-muted-foreground">
                        {" · "}
                        {Object.hasOwn(END_REASONS, e.reason)
                          ? t(`users.endReasons.${e.reason as EndReason}`)
                          : e.reason}
                      </span>
                    )}
                  </Td>
                  <Td>
                    {e.method
                      ? Object.hasOwn(METHODS, e.method)
                        ? t(`users.methods.${e.method as Method}`)
                        : e.method
                      : "—"}
                  </Td>
                  <Td className="font-mono text-xs">{e.ip ?? "—"}</Td>
                  <Td className="max-w-72 truncate" title={e.user_agent ?? ""}>
                    <Device ua={e.user_agent} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <LoadMore
            count={list.items.length}
            onClick={list.loadMore && (() => void list.loadMore?.())}
            busy={list.loadingMore}
          />
        </>
      )}
    </Section>
  )
}

type DialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  busy: boolean
  error: unknown
}

function EditDialog({
  user,
  onSave,
  languages,
  ...props
}: DialogProps & {
  user: UserEntry
  onSave: (u: UserUpdate) => void
  languages?: readonly string[]
}) {
  const { t } = useAdminMessages()
  return (
    <Dialog
      open={props.open}
      onOpenChange={(next) => !props.busy && props.onOpenChange(next)}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t("users.editTitle", { name: userName(user) })}
          </DialogTitle>
          <DialogDescription>{t("users.editDescription")}</DialogDescription>
        </DialogHeader>
        <EditForm
          user={user}
          onSave={onSave}
          languages={languages}
          {...props}
        />
      </DialogContent>
    </Dialog>
  )
}

/** The host's tags once each, plus the account's own tag if the host no longer offers it. */
function languageChoices(offered: readonly string[], current: string) {
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase()
  // The account's own spelling stands in for the host's, so it stays selected.
  const tags = offered.map((tag) =>
    current && same(tag, current) ? current : tag
  )
  if (current && !tags.includes(current)) tags.push(current)
  return tags.filter((tag, i) => tags.findIndex((t) => same(t, tag)) === i)
}

// Sends only the fields that changed; an emptied email or phone is removed.
function EditForm({
  user,
  onSave,
  busy,
  error,
  onOpenChange,
  languages,
}: DialogProps & {
  user: UserEntry
  onSave: (u: UserUpdate) => void
  languages?: readonly string[]
}) {
  const { t } = useAdminMessages()
  const { language } = useAdmin()
  const formId = useId()
  const ids = {
    username: useId(),
    email: useId(),
    phone: useId(),
    lang: useId(),
    mfa: useId(),
  }
  const [form, setForm] = useState({
    username: user.username,
    email: user.email ?? "",
    phone: user.phone_number ?? "",
    language: user.preferred_language ?? "",
    mfaRequired: user.mfa_required ?? false,
  })
  const set =
    (k: Exclude<keyof typeof form, "mfaRequired">) =>
    (e: { target: { value: string } }) =>
      setForm((f) => ({ ...f, [k]: e.target.value }))
  const changed = (now: string, was: string | null) =>
    now.trim() !== (was ?? "") ? now.trim() : undefined
  const update: UserUpdate = {
    username: changed(form.username, user.username) || undefined,
    email: changed(form.email, user.email),
    phoneNumber: changed(form.phone, user.phone_number),
    preferredLanguage: changed(form.language, user.preferred_language),
    mfaRequired:
      form.mfaRequired !== (user.mfa_required ?? false)
        ? form.mfaRequired
        : undefined,
  }
  const any = Object.values(update).some((v) => v !== undefined)
  return (
    <>
      <form
        id={formId}
        className="grid gap-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (any) onSave(update)
        }}
      >
        <FormField label={t("users.username")} htmlFor={ids.username}>
          <Input
            id={ids.username}
            required
            autoComplete="off"
            value={form.username}
            onChange={set("username")}
          />
        </FormField>
        <FormField label={t("users.email")} htmlFor={ids.email}>
          <Input
            id={ids.email}
            type="email"
            autoComplete="off"
            value={form.email}
            onChange={set("email")}
          />
        </FormField>
        <FormField
          label={t("users.phone")}
          hint={t("users.phoneHint")}
          htmlFor={ids.phone}
        >
          <Input
            id={ids.phone}
            type="tel"
            autoComplete="off"
            value={form.phone}
            onChange={set("phone")}
          />
        </FormField>
        <FormField
          label={t("users.language")}
          hint={languages?.length ? undefined : t("users.languageHint")}
          htmlFor={ids.lang}
        >
          {languages?.length ? (
            <Select
              id={ids.lang}
              value={form.language}
              onChange={set("language")}
            >
              <option value="">{t("users.languageNone")}</option>
              {languageChoices(languages, form.language).map((tag) => (
                <option key={tag} value={tag}>
                  {languageName(tag, language)}
                </option>
              ))}
            </Select>
          ) : (
            <Input
              id={ids.lang}
              autoComplete="off"
              value={form.language}
              onChange={set("language")}
            />
          )}
        </FormField>
        <FormField
          label={t("users.mfaRequired")}
          hint={t("users.mfaRequiredHint")}
          htmlFor={ids.mfa}
        >
          <Checkbox
            id={ids.mfa}
            checked={form.mfaRequired}
            onCheckedChange={(checked) =>
              setForm((f) => ({ ...f, mfaRequired: checked }))
            }
          />
        </FormField>
        <ErrorText error={error} />
      </form>
      <DialogFooter>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => onOpenChange(false)}
        >
          {t("common.cancel")}
        </Button>
        <Button type="submit" form={formId} disabled={busy || !any}>
          {t("common.save")}
        </Button>
      </DialogFooter>
    </>
  )
}

const ENDS = ["1", "7", "30", "never", "date"] as const
type End = (typeof ENDS)[number]

function BanDialog({
  name,
  warnings,
  onBan,
  ...props
}: DialogProps & {
  name: string
  warnings: { node: ReactNode; pending: boolean }
  onBan: (input: BanInput) => void
}) {
  const { t } = useAdminMessages()
  return (
    <Dialog
      open={props.open}
      onOpenChange={(next) => !props.busy && props.onOpenChange(next)}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("users.banTitle", { name })}</DialogTitle>
          <DialogDescription>{t("users.banDescription")}</DialogDescription>
        </DialogHeader>
        <BanForm warnings={warnings} onBan={onBan} {...props} />
      </DialogContent>
    </Dialog>
  )
}

function BanForm({
  warnings,
  onBan,
  busy,
  error,
  onOpenChange,
}: DialogProps & {
  warnings: { node: ReactNode; pending: boolean }
  onBan: (input: BanInput) => void
}) {
  const { t } = useAdminMessages()
  const formId = useId()
  const ids = { reason: useId(), end: useId(), date: useId() }
  const [reason, setReason] = useState("")
  const [end, setEnd] = useState<End>("7")
  const [date, setDate] = useState("")
  const label: Record<End, string> = {
    "1": t("users.banEnds.day"),
    "7": t("users.banEnds.week"),
    "30": t("users.banEnds.month"),
    never: t("users.banEnds.never"),
    date: t("users.banEnds.date"),
  }
  return (
    <>
      <form
        id={formId}
        className="grid gap-4"
        onSubmit={(e) => {
          e.preventDefault()
          const until =
            end === "never"
              ? null
              : end === "date"
                ? new Date(`${date}T23:59:59`).toISOString()
                : new Date(Date.now() + Number(end) * 86_400_000).toISOString()
          onBan({ reason: reason.trim() || undefined, until })
        }}
      >
        <FormField
          label={t("users.reason")}
          hint={t("users.reasonHint")}
          htmlFor={ids.reason}
        >
          <Input
            id={ids.reason}
            autoComplete="off"
            maxLength={500}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </FormField>
        <FormField label={t("users.banEnd")} htmlFor={ids.end}>
          <Select
            id={ids.end}
            value={end}
            onChange={(e) => setEnd(e.target.value as End)}
          >
            {ENDS.map((v) => (
              <option key={v} value={v}>
                {label[v]}
              </option>
            ))}
          </Select>
        </FormField>
        {end === "date" && (
          <FormField label={t("users.banEndDate")} htmlFor={ids.date}>
            <Input
              id={ids.date}
              type="date"
              required
              value={date}
              onChange={(e) => setDate(e.target.value)}
            />
          </FormField>
        )}
        {warnings.node}
        <ErrorText error={error} />
      </form>
      <DialogFooter>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => onOpenChange(false)}
        >
          {t("common.cancel")}
        </Button>
        <Button
          type="submit"
          form={formId}
          variant="destructive"
          disabled={busy || warnings.pending || (end === "date" && !date)}
        >
          {t("users.ban")}
        </Button>
      </DialogFooter>
    </>
  )
}
