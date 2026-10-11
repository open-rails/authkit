import { useId, useState } from "react"

import type {
  NewOAuthClient,
  OAuthClient,
  OAuthClientUpdate,
} from "../client/generated/wire.ts"
import { Notice } from "../components/account/shared.tsx"
import { Badge } from "../ui/badge.tsx"
import { Button, buttonVariants } from "../ui/button.tsx"
import { Input } from "../ui/input.tsx"
import { Textarea } from "../ui/textarea.tsx"
import { useAccessWith, type GroupAdminAccess } from "./access.ts"
import { useAdmin } from "./context.ts"
import { useAdminMessages, type AdminMessageKey } from "./i18n.ts"
import { Link } from "./link.tsx"
import { useLoad } from "./load.ts"
import {
  Body,
  ConfirmDialog,
  Empty,
  ErrorText,
  FormField,
  Loading,
  NoAccess,
  SecretField,
  Section,
  Select,
  Table,
  Td,
  Th,
  TypedConfirm,
} from "./parts.tsx"
import { AdminRoot, type GroupAdminProps } from "./root.tsx"
import { useNavigate, useRouter } from "./router.ts"
import { useActions } from "./write.ts"

export type OAuthClientsAdminProps = GroupAdminProps

/**
 * One group's OAuth clients (OpenID Connect apps that sign its users in):
 * register, edit redirect URIs and metadata, disable, rotate the secret,
 * delete. Views: `basePath`, `basePath/new`, `basePath/<client_id>`.
 */
export function OAuthClientsAdmin({ group, ...props }: OAuthClientsAdminProps) {
  return (
    <AdminRoot {...props}>
      <Clients group={group} />
    </AdminRoot>
  )
}

type Method = OAuthClient["token_endpoint_auth_method"]

const METHODS: [Method, AdminMessageKey][] = [
  ["client_secret_basic", "oauthClients.secretType"],
  ["none", "oauthClients.publicType"],
  ["private_key_jwt", "oauthClients.jwtType"],
]

const lines = (value: string) =>
  value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)

function Clients({ group }: { group: string }) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const { segments } = useRouter()
  const access = useAccessWith(client, group)
  const list = useLoad(
    access.credentials.read ? `clients:${group}` : null,
    (s) => client.listOAuthClients(group, s)
  )
  // A secret answered once, shown on the client's page it belongs to.
  const [secret, setSecret] = useState<{ id: string; value: string } | null>(
    null
  )
  if (access.status === "loading")
    return (
      <Section title={t("oauthClients.title")}>
        <Loading />
      </Section>
    )
  if (access.status === "error")
    return <ErrorText error={access.error} onRetry={access.reload} />
  if (!access.credentials.read) return <NoAccess />
  if (list.error && !list.data)
    return <ErrorText error={list.error} onRetry={list.reload} />
  if (!list.data)
    return (
      <Section title={t("oauthClients.title")}>
        <Loading />
      </Section>
    )
  const [first] = segments
  const props = { group, access, reload: list.reload, onSecret: setSecret }
  if (first === "new" && access.credentials.manage)
    return <NewClient {...props} />
  if (first) {
    const found = list.data.find((c) => c.client_id === first)
    if (!found)
      return (
        <Section title={t("oauthClients.title")}>
          <Empty>{t("oauthClients.notFound")}</Empty>
        </Section>
      )
    return (
      <ClientDetail
        {...props}
        key={found.client_id}
        found={found}
        secret={secret?.id === found.client_id ? secret.value : null}
      />
    )
  }
  return <ClientList access={access} clients={list.data} />
}

type Props = {
  group: string
  access: GroupAdminAccess
  reload: () => void
  onSecret: (secret: { id: string; value: string } | null) => void
}

function methodLabel(t: (k: AdminMessageKey) => string, m: Method) {
  const key = METHODS.find(([v]) => v === m)?.[1]
  return key ? t(key) : m
}

function ClientList({
  access,
  clients,
}: {
  access: GroupAdminAccess
  clients: OAuthClient[]
}) {
  const { t } = useAdminMessages()
  return (
    <Section
      title={t("oauthClients.title")}
      description={t("oauthClients.description")}
      actions={
        access.credentials.manage && (
          <Link to="new" className={buttonVariants()}>
            {t("oauthClients.newClient")}
          </Link>
        )
      }
    >
      {!clients.length ? (
        <Empty>{t("oauthClients.empty")}</Empty>
      ) : (
        <Table aria-label={t("oauthClients.title")}>
          <thead>
            <tr>
              <Th>{t("oauthClients.name")}</Th>
              <Th>{t("oauthClients.clientId")}</Th>
              <Th>{t("oauthClients.type")}</Th>
              <Th>{t("oauthClients.scope")}</Th>
            </tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.client_id}>
                <Td>
                  <span className="flex flex-wrap items-center gap-2">
                    <Link
                      to={encodeURIComponent(c.client_id)}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {c.client_name}
                    </Link>
                    {c.disabled && (
                      <Badge variant="secondary">{t("common.disabled")}</Badge>
                    )}
                  </span>
                </Td>
                <Td className="font-mono text-xs">{c.client_id}</Td>
                <Td>{methodLabel(t, c.token_endpoint_auth_method)}</Td>
                <Td className="text-xs">{c.scope}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Section>
  )
}

type Fields = {
  name: string
  redirects: string
  logouts: string
  scope: string
  jwksUri: string
  clientUri: string
  logoUri: string
  policyUri: string
  tosUri: string
}

const fieldsOf = (c?: OAuthClient): Fields => ({
  name: c?.client_name ?? "",
  redirects: c?.redirect_uris.join("\n") ?? "",
  logouts: c?.post_logout_redirect_uris.join("\n") ?? "",
  scope: c?.scope ?? "openid",
  jwksUri: c?.jwks_uri ?? "",
  clientUri: c?.client_uri ?? "",
  logoUri: c?.logo_uri ?? "",
  policyUri: c?.policy_uri ?? "",
  tosUri: c?.tos_uri ?? "",
})

// The registration's fields; a blank optional URL is none.
function ClientFields({
  value,
  onChange,
  method,
  disabled,
}: {
  value: Fields
  onChange: (next: Fields) => void
  method: Method
  disabled: boolean
}) {
  const { t } = useAdminMessages()
  const id = useId()
  const set = (key: keyof Fields) => (e: { target: { value: string } }) =>
    onChange({ ...value, [key]: e.target.value })
  const url = (key: keyof Fields, label: AdminMessageKey) => (
    <FormField
      label={t(label)}
      hint={t("oauthClients.optional")}
      htmlFor={`${id}-${key}`}
    >
      <Input
        id={`${id}-${key}`}
        type="url"
        value={value[key]}
        disabled={disabled}
        onChange={set(key)}
      />
    </FormField>
  )
  return (
    <>
      <FormField label={t("oauthClients.name")} htmlFor={`${id}-name`}>
        <Input
          id={`${id}-name`}
          required
          maxLength={120}
          value={value.name}
          disabled={disabled}
          onChange={set("name")}
        />
      </FormField>
      <FormField
        label={t("oauthClients.redirectUris")}
        htmlFor={`${id}-redirects`}
      >
        <Textarea
          id={`${id}-redirects`}
          required
          rows={3}
          className="font-mono text-xs"
          value={value.redirects}
          disabled={disabled}
          onChange={set("redirects")}
        />
      </FormField>
      <FormField
        label={t("oauthClients.scope")}
        hint={t("oauthClients.scopeHint")}
        htmlFor={`${id}-scope`}
      >
        <Input
          id={`${id}-scope`}
          value={value.scope}
          disabled={disabled}
          onChange={set("scope")}
        />
      </FormField>
      {method === "private_key_jwt" && url("jwksUri", "oauthClients.jwksUri")}
      <FormField
        label={t("oauthClients.logoutUris")}
        hint={t("oauthClients.optional")}
        htmlFor={`${id}-logouts`}
      >
        <Textarea
          id={`${id}-logouts`}
          rows={2}
          className="font-mono text-xs"
          value={value.logouts}
          disabled={disabled}
          onChange={set("logouts")}
        />
      </FormField>
      {url("clientUri", "oauthClients.clientUri")}
      {url("logoUri", "oauthClients.logoUri")}
      {url("policyUri", "oauthClients.policyUri")}
      {url("tosUri", "oauthClients.tosUri")}
    </>
  )
}

const blank = (s: string) => s.trim() || undefined

function NewClient({ group, reload, onSecret }: Props) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const navigate = useNavigate()
  const typeId = useId()
  const [fields, setFields] = useState(fieldsOf())
  const [method, setMethod] = useState<Method>("client_secret_basic")
  const actions = useActions(
    `authkit.oauth_clients:${group}`,
    { create: (d: NewOAuthClient) => client.createOAuthClient(group, d) },
    (_kind, made) => {
      onSecret(
        made.client_secret
          ? { id: made.client_id, value: made.client_secret }
          : null
      )
      reload()
      navigate(encodeURIComponent(made.client_id))
    }
  )
  return (
    <Section
      title={t("oauthClients.createTitle")}
      description={t("oauthClients.description")}
    >
      <Body>
        <form
          className="grid max-w-xl gap-4"
          onSubmit={(e) => {
            e.preventDefault()
            void actions.run("create", {
              client_name: fields.name.trim(),
              redirect_uris: lines(fields.redirects),
              post_logout_redirect_uris: lines(fields.logouts),
              token_endpoint_auth_method: method,
              jwks_uri:
                method === "private_key_jwt"
                  ? blank(fields.jwksUri)
                  : undefined,
              scope: blank(fields.scope),
              client_uri: blank(fields.clientUri),
              logo_uri: blank(fields.logoUri),
              policy_uri: blank(fields.policyUri),
              tos_uri: blank(fields.tosUri),
            })
          }}
        >
          <FormField label={t("oauthClients.type")} htmlFor={typeId}>
            <Select
              id={typeId}
              value={method}
              onChange={(e) => setMethod(e.target.value as Method)}
            >
              {METHODS.map(([value, label]) => (
                <option key={value} value={value}>
                  {t(label)}
                </option>
              ))}
            </Select>
          </FormField>
          <ClientFields
            value={fields}
            onChange={setFields}
            method={method}
            disabled={actions.busy}
          />
          <ErrorText error={actions.error} />
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              disabled={
                actions.busy ||
                !fields.name.trim() ||
                !lines(fields.redirects).length
              }
            >
              {t("oauthClients.create")}
            </Button>
            <Link to="" className={buttonVariants({ variant: "outline" })}>
              {t("common.cancel")}
            </Link>
          </div>
        </form>
      </Body>
    </Section>
  )
}

const opt = (s: string) => s.trim() || null

function ClientDetail({
  group,
  access,
  reload,
  onSecret,
  found,
  secret,
}: Props & { found: OAuthClient; secret: string | null }) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const navigate = useNavigate()
  const [fields, setFields] = useState(() => fieldsOf(found))
  const [status, setStatus] = useState("")
  const [rotating, setRotating] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const manage = access.credentials.manage
  const actions = useActions(
    `authkit.oauth_clients:${group}`,
    {
      update: (d: { id: string; changes: OAuthClientUpdate }) =>
        client.updateOAuthClient(group, d.id, d.changes),
      rotate: (d: { id: string }) =>
        client.rotateOAuthClientSecret(group, d.id),
      remove: (d: { id: string }) => client.deleteOAuthClient(group, d.id),
    },
    (kind, result, data) => {
      if (kind === "rotate") {
        onSecret({
          id: data.id,
          value: (result as { client_secret: string }).client_secret,
        })
        setRotating(false)
      } else if (kind === "remove") {
        setDeleting(false)
        onSecret(null)
        navigate("")
      } else {
        setStatus(
          t("oauthClients.saved", { name: (result as OAuthClient).client_name })
        )
      }
      reload()
    }
  )
  return (
    <Section
      title={
        <span className="flex flex-wrap items-center gap-2">
          {found.client_name}
          {found.disabled && (
            <Badge variant="secondary">{t("common.disabled")}</Badge>
          )}
        </span>
      }
      description={<span className="font-mono text-xs">{found.client_id}</span>}
      actions={
        <>
          <Link to="" className={buttonVariants({ variant: "outline" })}>
            {t("common.back")}
          </Link>
          {manage && (
            <>
              <Button
                variant="outline"
                disabled={actions.busy}
                onClick={() =>
                  void actions.run("update", {
                    id: found.client_id,
                    changes: { disabled: !found.disabled },
                  })
                }
              >
                {found.disabled ? t("common.enable") : t("common.disable")}
              </Button>
              {found.token_endpoint_auth_method === "client_secret_basic" && (
                <Button
                  variant="outline"
                  disabled={actions.busy}
                  onClick={() => setRotating(true)}
                >
                  {t("oauthClients.rotate")}
                </Button>
              )}
              <Button variant="destructive" onClick={() => setDeleting(true)}>
                {t("common.delete")}
              </Button>
            </>
          )}
        </>
      }
    >
      <Body>
        {secret && (
          <SecretField
            label={t("oauthClients.secret", { name: found.client_name })}
            value={secret}
          />
        )}
        <ErrorText error={actions.error} />
        {status && <Notice tone="success">{status}</Notice>}
        <p className="text-sm">
          {t("oauthClients.type")}:{" "}
          {methodLabel(t, found.token_endpoint_auth_method)}
        </p>
        <form
          className="grid max-w-xl gap-4"
          onSubmit={(e) => {
            e.preventDefault()
            setStatus("")
            void actions.run("update", {
              id: found.client_id,
              changes: {
                client_name: fields.name.trim(),
                redirect_uris: lines(fields.redirects),
                post_logout_redirect_uris: lines(fields.logouts),
                scope: opt(fields.scope),
                jwks_uri:
                  found.token_endpoint_auth_method === "private_key_jwt"
                    ? opt(fields.jwksUri)
                    : undefined,
                client_uri: opt(fields.clientUri),
                logo_uri: opt(fields.logoUri),
                policy_uri: opt(fields.policyUri),
                tos_uri: opt(fields.tosUri),
              },
            })
          }}
        >
          <ClientFields
            value={fields}
            onChange={setFields}
            method={found.token_endpoint_auth_method}
            disabled={!manage || actions.busy}
          />
          {manage && (
            <Button
              type="submit"
              className="justify-self-start"
              disabled={
                actions.busy ||
                !fields.name.trim() ||
                !lines(fields.redirects).length
              }
            >
              {t("common.save")}
            </Button>
          )}
        </form>
      </Body>
      <ConfirmDialog
        open={rotating}
        onOpenChange={setRotating}
        title={t("oauthClients.rotateTitle", { name: found.client_name })}
        description={t("oauthClients.rotateDescription")}
        confirmLabel={t("oauthClients.rotate")}
        busy={actions.busy}
        destructive
        onConfirm={() => void actions.run("rotate", { id: found.client_id })}
      />
      <TypedConfirm
        open={deleting}
        onOpenChange={setDeleting}
        title={t("oauthClients.deleteTitle", { name: found.client_name })}
        description={t("oauthClients.deleteDescription")}
        word={found.client_name}
        confirmLabel={t("common.delete")}
        busy={actions.busy}
        onConfirm={() => void actions.run("remove", { id: found.client_id })}
      />
    </Section>
  )
}
