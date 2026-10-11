import { useId, useState } from "react"

import type { GroupRole } from "../client/generated/wire.ts"
import { Badge } from "../ui/badge.tsx"
import { Button, buttonVariants } from "../ui/button.tsx"
import { Input } from "../ui/input.tsx"
import { useAccessWith, type GroupAdminAccess } from "./access.ts"
import { useAdmin } from "./context.ts"
import { useAdminMessages } from "./i18n.ts"
import { Link } from "./link.tsx"
import { useLoad } from "./load.ts"
import {
  Body,
  Empty,
  ErrorText,
  FormField,
  Loading,
  NoAccess,
  Section,
  Table,
  Td,
  Th,
  TypedConfirm,
} from "./parts.tsx"
import { AdminRoot, type GroupAdminProps } from "./root.tsx"
import {
  catalogOf,
  describePermission,
  ROLE_NAME,
  roleTitle,
  type PermissionHelp,
} from "./roles-lib.ts"
import { useNavigate, useRouter } from "./router.ts"
import { useActions } from "./write.ts"

export interface RolesAdminProps extends GroupAdminProps {
  /** Labels for the persona's own permissions, by permission or `resource:action`. */
  permissionHelp?: PermissionHelp
}

/**
 * One group's roles and what each grants; custom roles are created, edited
 * and deleted from the persona's permissions, never beyond the editor's own.
 * Views: `basePath`, `basePath/new`, `basePath/<role>`.
 */
export function RolesAdmin({
  group,
  permissionHelp,
  ...props
}: RolesAdminProps) {
  return (
    <AdminRoot {...props}>
      <Roles group={group} help={permissionHelp} />
    </AdminRoot>
  )
}

type View = { group: string; help?: PermissionHelp }

function Roles({ group, help }: View) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const { segments } = useRouter()
  const access = useAccessWith(client, group)
  const roles = useLoad(access.roles.read ? `roles:${group}` : null, (s) =>
    client.listRoles(group, s)
  )
  if (access.status === "loading")
    return (
      <Section title={t("roles.title")}>
        <Loading />
      </Section>
    )
  if (access.status === "error")
    return <ErrorText error={access.error} onRetry={access.reload} />
  if (!access.roles.read) return <NoAccess />
  if (roles.error && !roles.data)
    return <ErrorText error={roles.error} onRetry={roles.reload} />
  if (!roles.data)
    return (
      <Section title={t("roles.title")}>
        <Loading />
      </Section>
    )
  const [first] = segments
  const props = { group, help, access, roles: roles.data, reload: roles.reload }
  if (first === "new" && access.roles.manage) return <RoleEditor {...props} />
  if (first) {
    const role = roles.data.find((r) => r.name === first)
    if (!role)
      return (
        <Section title={t("roles.title")}>
          <Empty>{t("roles.notFound")}</Empty>
        </Section>
      )
    return segments[1] === "edit" && role.custom && access.roles.manage ? (
      <RoleEditor {...props} role={role} />
    ) : (
      <RoleDetail {...props} role={role} />
    )
  }
  return <RoleList {...props} />
}

type Props = View & {
  access: GroupAdminAccess
  roles: GroupRole[]
  reload: () => void
}

function Grants({ role, persona }: { role: GroupRole; persona: string }) {
  const { t } = useAdminMessages()
  return (
    <span className="flex flex-wrap gap-1">
      {role.grants.map((grant) => {
        const rest = grant.slice(grant.indexOf(":") + 1)
        const label =
          grant === `${persona}:*`
            ? t("roles.everything")
            : rest.endsWith(":*")
              ? t("roles.allOf", { resource: rest.slice(0, -2) })
              : rest
        return (
          <Badge key={grant} variant="secondary" title={grant}>
            {label}
          </Badge>
        )
      })}
    </span>
  )
}

function RoleBadges({ role }: { role: GroupRole }) {
  const { t } = useAdminMessages()
  return (
    <>
      <Badge variant={role.custom ? "secondary" : "outline"}>
        {role.custom ? t("roles.custom") : t("roles.builtIn")}
      </Badge>
      {role.requires_mfa && (
        <Badge variant="outline">{t("roles.requiresMfa")}</Badge>
      )}
    </>
  )
}

function RoleList({ access, roles }: Props) {
  const { t } = useAdminMessages()
  const persona = access.persona ?? ""
  return (
    <Section
      title={t("roles.title")}
      description={t("roles.description")}
      actions={
        access.roles.manage && (
          <Link to="new" className={buttonVariants()}>
            {t("roles.newRole")}
          </Link>
        )
      }
    >
      <Table aria-label={t("roles.title")}>
        <thead>
          <tr>
            <Th>{t("roles.role")}</Th>
            <Th>{t("roles.grants")}</Th>
          </tr>
        </thead>
        <tbody>
          {roles.map((role) => (
            <tr key={role.name}>
              <Td className="align-top">
                <div className="flex flex-wrap items-center gap-2">
                  <Link
                    to={encodeURIComponent(role.name)}
                    className="font-medium underline-offset-4 hover:underline"
                  >
                    {roleTitle(role.name)}
                  </Link>
                  <RoleBadges role={role} />
                </div>
                <span className="font-mono text-xs text-muted-foreground">
                  {role.name}
                </span>
              </Td>
              <Td className="align-top">
                <Grants role={role} persona={persona} />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Section>
  )
}

function RoleDetail({
  group,
  help,
  access,
  role,
  reload,
}: Props & { role: GroupRole }) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const navigate = useNavigate()
  const [deleting, setDeleting] = useState(false)
  const title = roleTitle(role.name)
  const actions = useActions(
    `authkit.roles:${group}`,
    { remove: (d: { role: string }) => client.deleteRole(group, d.role) },
    () => {
      setDeleting(false)
      reload()
      navigate("")
    }
  )
  const manage = role.custom && access.roles.manage
  return (
    <Section
      title={
        <span className="flex flex-wrap items-center gap-2">
          {title}
          <RoleBadges role={role} />
        </span>
      }
      description={<span className="font-mono text-xs">{role.name}</span>}
      actions={
        <>
          <Link to="" className={buttonVariants({ variant: "outline" })}>
            {t("common.back")}
          </Link>
          {manage && (
            <>
              <Link
                to={`${encodeURIComponent(role.name)}/edit`}
                className={buttonVariants({ variant: "outline" })}
              >
                {t("common.edit")}
              </Link>
              <Button variant="destructive" onClick={() => setDeleting(true)}>
                {t("common.delete")}
              </Button>
            </>
          )}
        </>
      }
    >
      <Body>
        <ErrorText error={actions.error} />
        <div className="grid gap-2">
          <h3 className="text-sm font-medium">{t("roles.grants")}</h3>
          <Grants role={role} persona={access.persona ?? ""} />
        </div>
        <div className="grid gap-2">
          <h3 className="text-sm font-medium">{t("roles.allows")}</h3>
          <ul className="grid gap-1.5" aria-label={t("roles.allows")}>
            {role.permissions.map((perm) => {
              const d = describePermission(perm, help, t)
              return (
                <li key={perm} className="grid">
                  <span className="text-sm">{d.label}</span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {perm}
                  </span>
                </li>
              )
            })}
          </ul>
        </div>
      </Body>
      <TypedConfirm
        open={deleting}
        onOpenChange={setDeleting}
        title={t("roles.deleteTitle", { role: title })}
        description={t("roles.deleteDescription")}
        word={title}
        confirmLabel={t("common.delete")}
        busy={actions.busy}
        onConfirm={() => void actions.run("remove", { role: role.name })}
      />
    </Section>
  )
}

function RoleEditor({
  group,
  help,
  access,
  roles,
  reload,
  role,
}: Props & { role?: GroupRole }) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const navigate = useNavigate()
  const nameId = useId()
  const persona = access.persona ?? ""
  const [name, setName] = useState("")
  const [selected, setSelected] = useState<ReadonlySet<string>>(
    () => new Set(role?.grants ?? [])
  )
  const actions = useActions(
    `authkit.roles:${group}`,
    {
      create: (d: { name: string; permissions: string[] }) =>
        client.createRole(group, d),
      update: (d: { role: string; permissions: string[] }) =>
        client.updateRole(group, d.role, d.permissions),
    },
    (_kind, made) => {
      reload()
      navigate(encodeURIComponent((made as GroupRole).name))
    }
  )
  const nameValid = !!role || ROLE_NAME.test(name)
  // A grant outside the catalog (a pattern set through the API) is offered
  // too, so an edit can keep or drop it.
  const offered = [
    ...new Set([...catalogOf(roles, persona), ...(role?.grants ?? [])]),
  ]
  const described = offered.map((perm) => ({
    perm,
    ...describePermission(perm, help, t),
  }))
  // On root, other personas' permissions apply in every group of theirs.
  const sections = new Map<string, typeof described>()
  for (const d of described) {
    const section = !d.perm.startsWith(`${persona}:`)
      ? t("roles.everyGroup", { persona: d.perm.slice(0, d.perm.indexOf(":")) })
      : d.builtIn
        ? t("roles.access")
        : d.section || t("roles.other")
    sections.set(section, [...(sections.get(section) ?? []), d])
  }
  const toggle = (perm: string, on: boolean) =>
    setSelected((current) => {
      const next = new Set(current)
      if (on) next.add(perm)
      else next.delete(perm)
      return next
    })
  const title = role ? roleTitle(role.name) : ""

  return (
    <Section
      title={
        role ? t("roles.editTitle", { role: title }) : t("roles.createTitle")
      }
      description={
        role ? t("roles.editDescription") : t("roles.createDescription")
      }
    >
      <Body>
        <form
          className="grid gap-5"
          onSubmit={(e) => {
            e.preventDefault()
            const permissions = [...selected]
            void (role
              ? actions.run("update", { role: role.name, permissions })
              : actions.run("create", { name, permissions }))
          }}
        >
          {!role && (
            <FormField
              label={t("roles.name")}
              hint={t("roles.nameHint", {
                role: `${persona}:custom-${name || "…"}`,
              })}
              htmlFor={nameId}
            >
              <Input
                id={nameId}
                value={name}
                maxLength={64}
                autoComplete="off"
                aria-invalid={name !== "" && !nameValid}
                onChange={(e) => setName(e.target.value.toLowerCase())}
              />
            </FormField>
          )}
          {[...sections].map(([section, perms]) => (
            <fieldset key={section} className="grid gap-2">
              <legend className="mb-1 text-sm font-semibold">{section}</legend>
              {perms.map((d) => {
                const held = access.permissions.has(d.perm)
                return (
                  <label
                    key={d.perm}
                    className="flex items-start gap-3 rounded-md border p-2.5 has-[:disabled]:opacity-60"
                    title={held ? undefined : t("roles.notHeld")}
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5 size-4 accent-primary"
                      checked={selected.has(d.perm)}
                      disabled={!held && !selected.has(d.perm)}
                      onChange={(e) => toggle(d.perm, e.target.checked)}
                    />
                    <span className="grid min-w-0 gap-0.5">
                      <span className="text-sm">{d.label}</span>
                      {d.description && (
                        <span className="text-xs text-muted-foreground">
                          {d.description}
                        </span>
                      )}
                      <span className="font-mono text-xs text-muted-foreground">
                        {d.perm}
                      </span>
                    </span>
                  </label>
                )
              })}
            </fieldset>
          ))}
          <ErrorText error={actions.error} />
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              disabled={actions.busy || !nameValid || selected.size === 0}
            >
              {role ? t("roles.save") : t("roles.create")}
            </Button>
            <Link
              to={role ? encodeURIComponent(role.name) : ""}
              className={buttonVariants({ variant: "outline" })}
            >
              {t("common.cancel")}
            </Link>
          </div>
        </form>
      </Body>
    </Section>
  )
}
