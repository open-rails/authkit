import { useCallback, useId, useState } from "react"

import type {
  GroupMember,
  GroupRole,
  Invitation,
} from "../client/generated/wire.ts"
import { Badge } from "../ui/badge.tsx"
import { Button } from "../ui/button.tsx"
import { Input } from "../ui/input.tsx"
import { Notice } from "../components/account/shared.tsx"
import { useAccessWith, type GroupAdminAccess } from "./access.ts"
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
  ViewTabs,
} from "./parts.tsx"
import { AdminRoot, type GroupAdminProps } from "./root.tsx"
import { ownerRole, roleTitle } from "./roles-lib.ts"
import { useRouter, useSearchParams } from "./router.ts"
import { useActions } from "./write.ts"
import { losesRoleAccess, type ReviewServiceKeys } from "./offboarding-lib.ts"
import { ServiceKeyReminder } from "./service-key-reminder.tsx"

export interface MembersAdminProps extends GroupAdminProps {
  /** Optional credential inventory for a post-removal reminder; never revokes keys. */
  onReviewServiceKeys?: ReviewServiceKeys
}

/**
 * One group's members and invitations: who holds which role, changing or
 * removing it, inviting by email or link. Views: `basePath` (members,
 * `?role=` filter) and `basePath/invitations`.
 */
export function MembersAdmin({
  group,
  onReviewServiceKeys,
  ...props
}: MembersAdminProps) {
  return (
    <AdminRoot {...props}>
      <Members
        key={group}
        group={group}
        onReviewServiceKeys={onReviewServiceKeys}
      />
    </AdminRoot>
  )
}

function Members({
  group,
  onReviewServiceKeys,
}: Pick<MembersAdminProps, "group" | "onReviewServiceKeys">) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const { segments } = useRouter()
  const access = useAccessWith(client, group)
  const roles = useLoad(access.roles.read ? `roles:${group}` : null, (s) =>
    client.listRoles(group, s)
  )
  if (access.status === "loading")
    return (
      <Section title={t("members.title")}>
        <Loading />
      </Section>
    )
  if (access.status === "error")
    return <ErrorText error={access.error} onRetry={access.reload} />
  if (!access.members.read && !access.invite) return <NoAccess />
  const view = segments[0] === "invitations" ? "invitations" : "members"
  const assignable = (roles.data ?? []).map((r) => r.name)
  return (
    <>
      {access.members.read && (
        <ViewTabs
          label={t("members.views")}
          items={[
            { to: "", label: t("members.title"), current: view === "members" },
            {
              to: "invitations",
              label: t("invitations.title"),
              current: view === "invitations",
            },
          ]}
        />
      )}
      {view === "members" && access.members.read ? (
        <MemberList
          group={group}
          access={access}
          roles={assignable}
          roleCatalog={roles.data ?? []}
          onReviewServiceKeys={onReviewServiceKeys}
        />
      ) : (
        <Invitations group={group} access={access} roles={assignable} />
      )}
    </>
  )
}

const memberName = (m: GroupMember) => m.user?.username || m.subject.id

function MemberList({
  group,
  access,
  roles,
  roleCatalog,
  onReviewServiceKeys,
}: {
  group: string
  access: GroupAdminAccess
  roles: string[]
  roleCatalog: readonly GroupRole[]
  onReviewServiceKeys?: ReviewServiceKeys
}) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const filterId = useId()
  const [search, setSearch] = useSearchParams()
  const role = search.get("role") ?? ""
  const [status, setStatus] = useState("")
  const [removing, setRemoving] = useState<GroupMember | null>(null)
  const [review, setReview] = useState<{ userId: string; name: string } | null>(
    null
  )
  const owner = access.persona ? ownerRole(access.persona) : ""
  const page = useCallback(
    (cursor?: string, signal?: AbortSignal) =>
      client.listMembers(
        group,
        { cursor, role: role ? [role] : undefined },
        signal
      ),
    [client, group, role]
  )
  const members = usePages(`members:${group}:${role}`, page)
  // Two owners or more: neither is the last.
  const owners = useLoad(owner ? `owners:${group}` : null, (signal) =>
    client.listMembers(group, { role: [owner], limit: 2 }, signal)
  )
  const lastOwner = (m: GroupMember) =>
    m.role === owner && owners.data?.data.length === 1
  const { reload } = members
  const { reload: reloadOwners } = owners
  const actions = useActions(
    `authkit.members:${group}`,
    {
      setRole: (d: {
        userId: string
        role: string
        previousRole: string
        name: string
      }) => client.setMemberRole(group, d.userId, d.role),
      remove: (d: { userId: string; name: string }) =>
        client.removeMember(group, d.userId),
    },
    (kind, _result, data) => {
      setReview(
        kind === "remove" ||
          losesRoleAccess(
            (data as { previousRole: string }).previousRole,
            (data as { role: string }).role,
            roleCatalog
          )
          ? { userId: data.userId, name: data.name }
          : null
      )
      setStatus(
        kind === "remove"
          ? t("members.removed", { name: data.name })
          : t("members.changed", {
              name: data.name,
              role: roleTitle((data as { role: string }).role),
            })
      )
      setRemoving(null)
      reload()
      reloadOwners()
    }
  )

  return (
    <Section
      title={t("members.title")}
      description={t("members.description")}
      actions={
        roles.length > 0 && (
          <div className="flex items-center gap-2">
            <label htmlFor={filterId} className="text-sm text-muted-foreground">
              {t("members.filter")}
            </label>
            <Select
              id={filterId}
              value={role}
              onChange={(e) => {
                const next = new URLSearchParams(search)
                if (e.target.value) next.set("role", e.target.value)
                else next.delete("role")
                setSearch(next)
              }}
            >
              <option value="">{t("members.allRoles")}</option>
              {roles.map((r) => (
                <option key={r} value={r}>
                  {roleTitle(r)}
                </option>
              ))}
            </Select>
          </div>
        )
      }
    >
      {(actions.error || status) && (
        <Body>
          <ErrorText error={actions.error} />
          {status && !actions.error && <Notice tone="success">{status}</Notice>}
        </Body>
      )}
      {review && (
        <Body>
          <ServiceKeyReminder
            name={review.name}
            onReview={
              onReviewServiceKeys &&
              (() => onReviewServiceKeys({ group, userId: review.userId }))
            }
            onDismiss={() => setReview(null)}
          />
        </Body>
      )}
      {members.loading ? (
        <Loading />
      ) : members.error && !members.items ? (
        <Body>
          <ErrorText error={members.error} onRetry={members.reload} />
        </Body>
      ) : !members.items?.length ? (
        <Empty>{role ? t("members.emptyFiltered") : t("members.empty")}</Empty>
      ) : (
        <>
          <Table aria-label={t("members.title")}>
            <thead>
              <tr>
                <Th>{t("members.member")}</Th>
                <Th>{t("members.role")}</Th>
                {access.members.manage && (
                  <Th className="text-right">{t("common.actions")}</Th>
                )}
              </tr>
            </thead>
            <tbody>
              {members.items.map((m) => {
                const name = memberName(m)
                const pinned = lastOwner(m)
                return (
                  <tr key={m.subject.id}>
                    <Td>
                      <div className="grid">
                        <span className="font-medium">{name}</span>
                        <span className="font-mono text-xs text-muted-foreground">
                          {m.subject.id}
                        </span>
                      </div>
                    </Td>
                    <Td>
                      {access.members.manage ? (
                        <Select
                          aria-label={t("members.roleOf", { name })}
                          value={m.role}
                          title={pinned ? t("members.lastOwner") : undefined}
                          disabled={actions.busy || pinned}
                          onChange={(e) =>
                            void actions.run("setRole", {
                              userId: m.subject.id,
                              role: e.target.value,
                              previousRole: m.role,
                              name,
                            })
                          }
                        >
                          {[...new Set([m.role, ...roles])].map((r) => (
                            <option key={r} value={r}>
                              {roleTitle(r)}
                            </option>
                          ))}
                        </Select>
                      ) : (
                        <Badge variant="secondary">{roleTitle(m.role)}</Badge>
                      )}
                    </Td>
                    {access.members.manage && (
                      <Td className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={actions.busy || pinned}
                          title={pinned ? t("members.lastOwner") : undefined}
                          aria-label={`${t("common.remove")}: ${name}`}
                          onClick={() => setRemoving(m)}
                        >
                          {t("common.remove")}
                        </Button>
                      </Td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </Table>
          <LoadMore
            count={members.items.length}
            onClick={members.loadMore && (() => void members.loadMore?.())}
            busy={members.loadingMore}
          />
        </>
      )}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={t("members.removeTitle", {
          name: removing ? memberName(removing) : "",
        })}
        description={t("members.removeDescription")}
        confirmLabel={t("common.remove")}
        busy={actions.busy}
        destructive
        onConfirm={() =>
          removing &&
          void actions.run("remove", {
            userId: removing.subject.id,
            name: memberName(removing),
          })
        }
      >
        {removing && (
          <p className="text-sm text-muted-foreground">
            {t("offboarding.reminder", { name: memberName(removing) })}
          </p>
        )}
        <ErrorText error={actions.error} />
      </ConfirmDialog>
    </Section>
  )
}

function invitationState(i: Invitation) {
  if (i.revoked_at) return "revoked" as const
  if (i.redeemed_at) return "accepted" as const
  if (i.expires_at && Date.parse(i.expires_at) < Date.now())
    return "expired" as const
  return "pending" as const
}

export function Invitations({
  group,
  access,
  roles,
}: {
  group: string
  access: GroupAdminAccess
  roles: string[]
}) {
  const { t } = useAdminMessages()
  const { client, language } = useAdmin()
  const emailId = useId()
  const roleId = useId()
  const root = access.persona === "root"
  const [email, setEmail] = useState("")
  const [role, setRole] = useState("")
  const [link, setLink] = useState<string | null>(null)
  const [status, setStatus] = useState("")
  const [revoking, setRevoking] = useState<Invitation | null>(null)
  const page = useCallback(
    (cursor?: string, signal?: AbortSignal) =>
      client.listInvitations(group, { cursor }, signal),
    [client, group]
  )
  const list = usePages(
    access.members.read ? `invitations:${group}` : null,
    page
  )
  const { reload } = list
  const actions = useActions(
    `authkit.invitations:${group}`,
    {
      create: (d: { email: string; role: string }) =>
        client.createInvitation(group, d),
      revoke: (d: { id: string }) => client.revokeInvitation(group, d.id),
    },
    (kind, result, data) => {
      if (kind === "create") {
        const made = result as Awaited<
          ReturnType<typeof client.createInvitation>
        >
        setLink(made?.url ?? null)
        const sentTo = (data as { email: string }).email
        setStatus(sentTo ? t("invitations.sent", { email: sentTo }) : "")
        setEmail("")
      } else {
        setStatus(t("invitations.revokedDone"))
        setRevoking(null)
      }
      reload()
    }
  )
  // Without a role, only an email to root invites someone to register.
  const roleOptional = root && email.trim() !== ""
  const chosen = role || (roleOptional ? "" : (roles[0] ?? ""))

  return (
    <div className="grid gap-6">
      {access.invite && (
        <Section
          title={t("invitations.title")}
          description={t("invitations.description")}
        >
          <Body>
            <form
              className="grid gap-4 sm:grid-cols-[1fr_14rem_auto] sm:items-end"
              onSubmit={(e) => {
                e.preventDefault()
                setLink(null)
                setStatus("")
                void actions.run("create", {
                  email: email.trim(),
                  role: chosen,
                })
              }}
            >
              <FormField
                label={t("invitations.email")}
                hint={t("invitations.emailHint")}
                htmlFor={emailId}
              >
                <Input
                  id={emailId}
                  type="email"
                  autoComplete="off"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </FormField>
              <FormField label={t("invitations.role")} htmlFor={roleId}>
                <Select
                  id={roleId}
                  value={chosen}
                  onChange={(e) => setRole(e.target.value)}
                >
                  {roleOptional && (
                    <option value="">{t("invitations.noRole")}</option>
                  )}
                  {roles.map((r) => (
                    <option key={r} value={r}>
                      {roleTitle(r)}
                    </option>
                  ))}
                </Select>
              </FormField>
              <Button
                type="submit"
                disabled={actions.busy || (!chosen && !roleOptional)}
                className="sm:mb-[1.375rem]"
              >
                {t("invitations.send")}
              </Button>
            </form>
            <ErrorText error={actions.error} />
            {link && <SecretField label={t("invitations.link")} value={link} />}
            {status && <Notice tone="success">{status}</Notice>}
          </Body>
        </Section>
      )}
      {access.members.read && (
        <Section title={t("invitations.list")}>
          {list.loading ? (
            <Loading />
          ) : list.error && !list.items ? (
            <Body>
              <ErrorText error={list.error} onRetry={list.reload} />
            </Body>
          ) : !list.items?.length ? (
            <Empty>{t("invitations.empty")}</Empty>
          ) : (
            <>
              <Table aria-label={t("invitations.list")}>
                <thead>
                  <tr>
                    <Th>{t("invitations.recipient")}</Th>
                    <Th>{t("invitations.role")}</Th>
                    <Th>{t("invitations.created")}</Th>
                    <Th>{t("invitations.expires")}</Th>
                    <Th>{t("invitations.status")}</Th>
                    {access.invite && (
                      <Th className="text-right">{t("common.actions")}</Th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {list.items.map((i) => {
                    const state = invitationState(i)
                    return (
                      <tr key={i.id}>
                        <Td>{i.email ?? t("invitations.anyone")}</Td>
                        <Td>{i.role ? roleTitle(i.role) : "—"}</Td>
                        <Td className="whitespace-nowrap">
                          {dateTime(i.created_at, language)}
                        </Td>
                        <Td className="whitespace-nowrap">
                          {dateTime(i.expires_at, language) || "—"}
                        </Td>
                        <Td>
                          <Badge
                            variant={
                              state === "pending" ? "outline" : "secondary"
                            }
                          >
                            {t(`invitations.${state}`)}
                          </Badge>
                        </Td>
                        {access.invite && (
                          <Td className="text-right">
                            {state === "pending" && (
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={actions.busy}
                                onClick={() => setRevoking(i)}
                              >
                                {t("common.revoke")}
                              </Button>
                            )}
                          </Td>
                        )}
                      </tr>
                    )
                  })}
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
      )}
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={t("invitations.revokeTitle")}
        description={t("invitations.revokeDescription")}
        confirmLabel={t("common.revoke")}
        busy={actions.busy}
        destructive
        onConfirm={() =>
          revoking && void actions.run("revoke", { id: revoking.id })
        }
      />
    </div>
  )
}
