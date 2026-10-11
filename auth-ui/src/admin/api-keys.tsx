import { useCallback, useId, useState } from "react"

import type { APIKey, APIKeyCreated } from "../client/generated/wire.ts"
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
import { useAccessWith } from "./access.ts"
import { useAdmin } from "./context.ts"
import { dateTime } from "./format.ts"
import { useAdminMessages } from "./i18n.ts"
import { useLoad } from "./load.ts"
import { usePages } from "./pages.ts"
import {
  Body,
  ConfirmDialog,
  Empty,
  ErrorText,
  FormField,
  LoadMore,
  Loading,
  NoAccess,
  SecretField,
  Section,
  Select,
  Table,
  Td,
  Th,
} from "./parts.tsx"
import { AdminRoot, type GroupAdminProps } from "./root.tsx"
import { roleTitle } from "./roles-lib.ts"
import { useSearchParams } from "./router.ts"
import { useActions } from "./write.ts"

export type ApiKeysAdminProps = GroupAdminProps

/**
 * One group's API keys: each holds one role; minting shows its secret once;
 * revoking refuses it at once. `?revoked=1` lists revoked keys too.
 */
export function ApiKeysAdmin({ group, ...props }: ApiKeysAdminProps) {
  return (
    <AdminRoot {...props}>
      <ApiKeys group={group} />
    </AdminRoot>
  )
}

const expired = (k: APIKey) =>
  !!k.expires_at && Date.parse(k.expires_at) < Date.now()

function ApiKeys({ group }: { group: string }) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const access = useAccessWith(client, group)
  const [search, setSearch] = useSearchParams()
  const showRevoked = search.get("revoked") === "1"
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState<APIKeyCreated | null>(null)
  const [revoking, setRevoking] = useState<APIKey | null>(null)
  const [status, setStatus] = useState("")
  const page = useCallback(
    (cursor?: string, signal?: AbortSignal) =>
      client.listAPIKeys(group, { cursor }, signal),
    [client, group]
  )
  const keys = usePages(access.credentials.read ? `keys:${group}` : null, page)
  const roles = useLoad(
    access.credentials.manage && access.roles.read ? `roles:${group}` : null,
    (s) => client.listRoles(group, s)
  )
  const { reload } = keys
  const actions = useActions(
    `authkit.api_keys:${group}`,
    {
      create: (d: { name: string; role: string; expiresAt: string | null }) =>
        client.createAPIKey(group, d),
      revoke: (d: { id: string; name: string }) =>
        client.revokeAPIKey(group, d.id),
    },
    (kind, result, data) => {
      if (kind === "create") {
        setCreated(result as APIKeyCreated)
        setCreating(true)
      } else {
        setStatus(t("apiKeys.revokedDone", { name: data.name }))
        setRevoking(null)
      }
      reload()
    }
  )

  if (access.status === "loading")
    return (
      <Section title={t("apiKeys.title")}>
        <Loading />
      </Section>
    )
  if (access.status === "error")
    return <ErrorText error={access.error} onRetry={access.reload} />
  if (!access.credentials.read) return <NoAccess />
  const shown = (keys.items ?? []).filter((k) => showRevoked || !k.revoked_at)

  return (
    <Section
      title={t("apiKeys.title")}
      description={t("apiKeys.description")}
      actions={
        <>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <input
              type="checkbox"
              className="size-4 accent-primary"
              checked={showRevoked}
              onChange={(e) => {
                const next = new URLSearchParams(search)
                if (e.target.checked) next.set("revoked", "1")
                else next.delete("revoked")
                setSearch(next, { replace: true })
              }}
            />
            {t("apiKeys.showRevoked")}
          </label>
          {access.credentials.manage && (
            <Button
              onClick={() => {
                actions.clear()
                setCreated(null)
                setCreating(true)
              }}
            >
              {t("apiKeys.newKey")}
            </Button>
          )}
        </>
      }
    >
      {(status || (actions.error && !creating)) && (
        <Body>
          {!creating && <ErrorText error={actions.error} />}
          {status && <Notice tone="success">{status}</Notice>}
        </Body>
      )}
      {keys.loading ? (
        <Loading />
      ) : keys.error && !keys.items ? (
        <Body>
          <ErrorText error={keys.error} onRetry={keys.reload} />
        </Body>
      ) : !shown.length ? (
        <Empty>{t("apiKeys.empty")}</Empty>
      ) : (
        <>
          <Table aria-label={t("apiKeys.title")}>
            <thead>
              <tr>
                <Th>{t("apiKeys.name")}</Th>
                <Th>{t("apiKeys.key")}</Th>
                <Th>{t("apiKeys.role")}</Th>
                <Th>{t("apiKeys.created")}</Th>
                <Th>{t("apiKeys.lastUsed")}</Th>
                <Th>{t("apiKeys.expires")}</Th>
                {access.credentials.manage && (
                  <Th className="text-right">{t("common.actions")}</Th>
                )}
              </tr>
            </thead>
            <tbody>
              {shown.map((k) => (
                <tr key={k.id}>
                  <Td>
                    <span className="flex flex-wrap items-center gap-2 font-medium">
                      {k.name}
                      {k.revoked_at ? (
                        <Badge variant="secondary">
                          {t("apiKeys.revoked")}
                        </Badge>
                      ) : (
                        expired(k) && (
                          <Badge variant="secondary">
                            {t("apiKeys.expired")}
                          </Badge>
                        )
                      )}
                    </span>
                  </Td>
                  <Td className="font-mono text-xs">{k.lookup_id}</Td>
                  <Td>{roleTitle(k.role)}</Td>
                  <Td className="whitespace-nowrap">
                    {dateTime(k.created_at)}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {dateTime(k.last_used_at) || t("common.never")}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {dateTime(k.expires_at) || "—"}
                  </Td>
                  {access.credentials.manage && (
                    <Td className="text-right">
                      {!k.revoked_at && (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={actions.busy}
                          aria-label={`${t("common.revoke")}: ${k.name}`}
                          onClick={() => setRevoking(k)}
                        >
                          {t("common.revoke")}
                        </Button>
                      )}
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
          <LoadMore
            count={shown.length}
            onClick={keys.loadMore && (() => void keys.loadMore?.())}
            busy={keys.loadingMore}
          />
        </>
      )}
      <MintDialog
        open={creating}
        onOpenChange={setCreating}
        roles={roles.data ?? []}
        created={created}
        busy={actions.busy}
        error={actions.error}
        onMint={(input) => void actions.run("create", input)}
      />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={t("apiKeys.revokeTitle", { name: revoking?.name ?? "" })}
        description={t("apiKeys.revokeDescription")}
        confirmLabel={t("common.revoke")}
        busy={actions.busy}
        destructive
        onConfirm={() =>
          revoking &&
          void actions.run("revoke", { id: revoking.id, name: revoking.name })
        }
      />
    </Section>
  )
}

function MintDialog({
  open,
  onOpenChange,
  roles,
  created,
  busy,
  error,
  onMint,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  roles: { name: string; requires_mfa: boolean }[]
  created: APIKeyCreated | null
  busy: boolean
  error: unknown
  onMint: (input: {
    name: string
    role: string
    expiresAt: string | null
  }) => void
}) {
  const { t } = useAdminMessages()
  const nameId = useId()
  const roleId = useId()
  const expiresId = useId()
  const [name, setName] = useState("")
  const [role, setRole] = useState("")
  const [expires, setExpires] = useState("")
  const usable = roles.filter((r) => !r.requires_mfa)
  const chosen = role || usable[0]?.name || ""
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("apiKeys.createTitle")}</DialogTitle>
          <DialogDescription>
            {t("apiKeys.createDescription")}
          </DialogDescription>
        </DialogHeader>
        {created ? (
          <SecretField
            label={t("apiKeys.secret", { name: created.api_key.name })}
            value={created.secret}
          />
        ) : (
          <form
            id={nameId + "-form"}
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault()
              onMint({
                name: name.trim(),
                role: chosen,
                expiresAt: expires
                  ? new Date(`${expires}T23:59:59Z`).toISOString()
                  : null,
              })
            }}
          >
            <FormField label={t("apiKeys.name")} htmlFor={nameId}>
              <Input
                id={nameId}
                required
                maxLength={120}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </FormField>
            <FormField label={t("apiKeys.role")} htmlFor={roleId}>
              <Select
                id={roleId}
                value={chosen}
                onChange={(e) => setRole(e.target.value)}
              >
                {roles.map((r) => (
                  <option key={r.name} value={r.name} disabled={r.requires_mfa}>
                    {r.requires_mfa
                      ? t("apiKeys.mfaRole", { role: roleTitle(r.name) })
                      : roleTitle(r.name)}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField
              label={t("apiKeys.expires")}
              hint={t("apiKeys.expiresHint")}
              htmlFor={expiresId}
            >
              <Input
                id={expiresId}
                type="date"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
              />
            </FormField>
            <ErrorText error={error} />
          </form>
        )}
        <DialogFooter>
          {created ? (
            <Button onClick={() => onOpenChange(false)}>
              {t("common.close")}
            </Button>
          ) : (
            <>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => onOpenChange(false)}
              >
                {t("common.cancel")}
              </Button>
              <Button
                type="submit"
                form={nameId + "-form"}
                disabled={busy || !name.trim() || !chosen}
              >
                {t("apiKeys.create")}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
