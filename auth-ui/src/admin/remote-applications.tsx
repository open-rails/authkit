import { useCallback, useId, useState } from "react"

import type { RemoteApplication } from "../client/generated/wire.ts"
import { Notice } from "../components/account/shared.tsx"
import { Badge } from "../ui/badge.tsx"
import { Button } from "../ui/button.tsx"
import { Input } from "../ui/input.tsx"
import { Textarea } from "../ui/textarea.tsx"
import { useAccessWith, type GroupAdminAccess } from "./access.ts"
import { useAdmin } from "./context.ts"
import { useAdminMessages } from "./i18n.ts"
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
  Section,
  Select,
  Table,
  Td,
  Th,
} from "./parts.tsx"
import { AdminRoot, type GroupAdminProps } from "./root.tsx"
import { roleTitle } from "./roles-lib.ts"
import { useActions } from "./write.ts"

export interface RemoteApplicationsAdminProps extends GroupAdminProps {
  /** The token endpoint assertions are sent to (their aud). Default `/oauth2/token` beside the API mount. */
  tokenEndpoint?: string
  /** A scope to show in the token request, such as `openrails:self`. */
  scope?: string
}

/**
 * One group's remote applications: a backend's signing keys for the RFC
 * 7523 assertions it trades for its users' tokens. Register a JWKS URL or a
 * PEM key, disable, delete; shows the assertion to sign.
 */
export function RemoteApplicationsAdmin({
  group,
  tokenEndpoint,
  scope,
  ...props
}: RemoteApplicationsAdminProps) {
  const base = (props.baseUrl ?? "/api/v1").replace(/\/+$/, "")
  const endpoint =
    tokenEndpoint ??
    new URL(
      `${base.replace(/\/api\/v1$/, "")}/oauth2/token`,
      globalThis.location?.origin ?? "http://localhost"
    ).toString()
  return (
    <AdminRoot {...props}>
      <Applications group={group} endpoint={endpoint} scope={scope} />
    </AdminRoot>
  )
}

const ISSUER_PLACEHOLDER = "https://shop.example.com"

function Applications({
  group,
  endpoint,
  scope,
}: {
  group: string
  endpoint: string
  scope?: string
}) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const access = useAccessWith(client, group)
  const [typed, setTyped] = useState("")
  const page = useCallback(
    (cursor?: string, signal?: AbortSignal) =>
      client.listRemoteApplications(group, { cursor }, signal),
    [client, group]
  )
  const apps = usePages(
    access.credentials.read ? `remote-apps:${group}` : null,
    page
  )
  if (access.status === "loading")
    return (
      <Section title={t("remoteApps.title")}>
        <Loading />
      </Section>
    )
  if (access.status === "error")
    return <ErrorText error={access.error} onRetry={access.reload} />
  if (!access.credentials.read) return <NoAccess />
  return (
    <>
      <AppList group={group} access={access} apps={apps} onIssuer={setTyped} />
      <SignThis
        issuer={apps.items?.[0]?.issuer || typed || ISSUER_PLACEHOLDER}
        endpoint={endpoint}
        scope={scope}
      />
    </>
  )
}

function keySummary(a: RemoteApplication) {
  return a.mode === "static"
    ? a.public_keys.map((k) => k.kid ?? "").join(", ")
    : (a.jwks_uri ?? "")
}

function AppList({
  group,
  access,
  apps,
  onIssuer,
}: {
  group: string
  access: GroupAdminAccess
  apps: ReturnType<typeof usePages<RemoteApplication>>
  onIssuer: (issuer: string) => void
}) {
  const { t } = useAdminMessages()
  const { client } = useAdmin()
  const id = useId()
  const [issuer, setIssuer] = useState("")
  const [source, setSource] = useState<"jwks" | "pem">("jwks")
  const [jwks, setJwks] = useState("")
  const [kid, setKid] = useState("")
  const [pem, setPem] = useState("")
  const [status, setStatus] = useState("")
  const [deleting, setDeleting] = useState<RemoteApplication | null>(null)
  const { reload } = apps
  const actions = useActions(
    `authkit.remote_applications:${group}`,
    {
      create: (d: Parameters<typeof client.createRemoteApplication>[1]) =>
        client.createRemoteApplication(group, d),
      enable: (d: { id: string; issuer: string; enabled: boolean }) =>
        client.updateRemoteApplication(group, d.id, { enabled: d.enabled }),
      remove: (d: { id: string; issuer: string }) =>
        client.deleteRemoteApplication(group, d.id),
    },
    (kind, _result, data) => {
      const name = (data as { issuer: string }).issuer
      if (kind === "create") {
        setStatus(t("remoteApps.registered", { issuer: name }))
        setIssuer("")
        setJwks("")
        setKid("")
        setPem("")
        onIssuer("")
      } else if (kind === "remove") {
        setStatus(t("remoteApps.deleted", { issuer: name }))
        setDeleting(null)
      } else {
        setStatus(
          (data as { enabled: boolean }).enabled
            ? t("remoteApps.enabledDone", { issuer: name })
            : t("remoteApps.disabledDone", { issuer: name })
        )
      }
      reload()
    }
  )
  const manage = access.credentials.manage
  const ready =
    issuer.trim() !== "" &&
    (source === "jwks"
      ? jwks.trim() !== ""
      : kid.trim() !== "" && pem.trim() !== "")

  return (
    <Section
      title={t("remoteApps.title")}
      description={t("remoteApps.description")}
    >
      {manage && (
        <Body>
          <form
            className="grid max-w-xl gap-4"
            onSubmit={(e) => {
              e.preventDefault()
              setStatus("")
              void actions.run(
                "create",
                source === "jwks"
                  ? { issuer: issuer.trim(), jwksUri: jwks.trim() }
                  : {
                      issuer: issuer.trim(),
                      publicKeys: [
                        { kid: kid.trim(), public_key_pem: pem.trim() },
                      ],
                    }
              )
            }}
          >
            <FormField
              label={t("remoteApps.issuer")}
              hint={t("remoteApps.issuerHint")}
              htmlFor={`${id}-issuer`}
            >
              <Input
                id={`${id}-issuer`}
                type="url"
                required
                placeholder={ISSUER_PLACEHOLDER}
                value={issuer}
                onChange={(e) => {
                  setIssuer(e.target.value)
                  onIssuer(e.target.value.trim())
                }}
              />
            </FormField>
            <FormField label={t("remoteApps.source")} htmlFor={`${id}-source`}>
              <Select
                id={`${id}-source`}
                value={source}
                onChange={(e) => setSource(e.target.value as "jwks" | "pem")}
              >
                <option value="jwks">{t("remoteApps.jwks")}</option>
                <option value="pem">{t("remoteApps.pem")}</option>
              </Select>
            </FormField>
            {source === "jwks" ? (
              <FormField label={t("remoteApps.jwksUri")} htmlFor={`${id}-jwks`}>
                <Input
                  id={`${id}-jwks`}
                  type="url"
                  required
                  placeholder={`${ISSUER_PLACEHOLDER}/.well-known/jwks.json`}
                  value={jwks}
                  onChange={(e) => setJwks(e.target.value)}
                />
              </FormField>
            ) : (
              <>
                <FormField
                  label={t("remoteApps.kid")}
                  hint={t("remoteApps.kidHint")}
                  htmlFor={`${id}-kid`}
                >
                  <Input
                    id={`${id}-kid`}
                    required
                    maxLength={120}
                    value={kid}
                    onChange={(e) => setKid(e.target.value)}
                  />
                </FormField>
                <FormField
                  label={t("remoteApps.publicKey")}
                  htmlFor={`${id}-pem`}
                >
                  <Textarea
                    id={`${id}-pem`}
                    required
                    rows={5}
                    className="font-mono text-xs"
                    placeholder="-----BEGIN PUBLIC KEY-----"
                    value={pem}
                    onChange={(e) => setPem(e.target.value)}
                  />
                </FormField>
              </>
            )}
            <Button
              type="submit"
              className="justify-self-start"
              disabled={actions.busy || !ready}
            >
              {t("remoteApps.register")}
            </Button>
          </form>
        </Body>
      )}
      {(actions.error || status) && (
        <Body>
          <ErrorText error={actions.error} />
          {status && !actions.error && <Notice tone="success">{status}</Notice>}
        </Body>
      )}
      {apps.loading ? (
        <Loading />
      ) : apps.error && !apps.items ? (
        <Body>
          <ErrorText error={apps.error} onRetry={apps.reload} />
        </Body>
      ) : !apps.items?.length ? (
        <Empty>{t("remoteApps.empty")}</Empty>
      ) : (
        <>
          <Table aria-label={t("remoteApps.list")}>
            <thead>
              <tr>
                <Th>{t("remoteApps.issuer")}</Th>
                <Th>{t("remoteApps.key")}</Th>
                <Th>{t("remoteApps.status")}</Th>
                {manage && (
                  <Th className="text-right">{t("common.actions")}</Th>
                )}
              </tr>
            </thead>
            <tbody>
              {apps.items.map((a) => {
                const operator = a.trust_root === "manual"
                return (
                  <tr key={a.id}>
                    <Td className="font-mono text-xs">{a.issuer}</Td>
                    <Td className="font-mono text-xs break-all">
                      {keySummary(a)}
                    </Td>
                    <Td>
                      <span className="flex flex-wrap gap-1">
                        <Badge variant={a.enabled ? "outline" : "secondary"}>
                          {a.enabled
                            ? t("common.enabled")
                            : t("common.disabled")}
                        </Badge>
                        {a.role && (
                          <Badge variant="secondary">{roleTitle(a.role)}</Badge>
                        )}
                        {operator && (
                          <Badge variant="secondary">
                            {t("remoteApps.operator")}
                          </Badge>
                        )}
                      </span>
                    </Td>
                    {manage && (
                      <Td className="text-right whitespace-nowrap">
                        {!operator && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={actions.busy}
                              aria-label={`${a.enabled ? t("common.disable") : t("common.enable")}: ${a.issuer}`}
                              onClick={() =>
                                void actions.run("enable", {
                                  id: a.id,
                                  issuer: a.issuer,
                                  enabled: !a.enabled,
                                })
                              }
                            >
                              {a.enabled
                                ? t("common.disable")
                                : t("common.enable")}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={actions.busy}
                              aria-label={`${t("common.delete")}: ${a.issuer}`}
                              onClick={() => setDeleting(a)}
                            >
                              {t("common.delete")}
                            </Button>
                          </>
                        )}
                      </Td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </Table>
          <LoadMore
            count={apps.items.length}
            onClick={apps.loadMore && (() => void apps.loadMore?.())}
            busy={apps.loadingMore}
          />
        </>
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t("remoteApps.deleteTitle", { issuer: deleting?.issuer ?? "" })}
        description={t("remoteApps.deleteDescription")}
        confirmLabel={t("common.delete")}
        busy={actions.busy}
        destructive
        onConfirm={() =>
          deleting &&
          void actions.run("remove", {
            id: deleting.id,
            issuer: deleting.issuer,
          })
        }
      />
    </Section>
  )
}

const code =
  "rounded-md border bg-muted/40 p-3 font-mono text-xs overflow-x-auto"

// The assertion a registered backend signs for one user, and how it
// becomes that user's token.
function SignThis({
  issuer,
  endpoint,
  scope,
}: {
  issuer: string
  endpoint: string
  scope?: string
}) {
  const { t } = useAdminMessages()
  const claims = `{
  "iss": "${issuer}",
  "sub": "<user id>",
  "aud": "${endpoint}",
  "iat": <now>,
  "exp": <now + 120>,
  "jti": "<random, used once>"
}`
  const redeem = `POST ${endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<the signed JWT>${scope ? `&scope=${scope}` : ""}`
  return (
    <Section title={t("remoteApps.signTitle")}>
      <Body>
        <p className="text-sm text-muted-foreground">
          {t("remoteApps.signIntro")}
        </p>
        <pre className={code}>{claims}</pre>
        <ul className="grid list-disc gap-1 pl-5 text-sm text-muted-foreground">
          <li>{t("remoteApps.signSub")}</li>
          <li>{t("remoteApps.signExp")}</li>
          <li>{t("remoteApps.signJti")}</li>
          <li>{t("remoteApps.signEmail")}</li>
        </ul>
        <p className="text-sm text-muted-foreground">
          {t("remoteApps.redeem")}
        </p>
        <pre className={code}>{redeem}</pre>
      </Body>
    </Section>
  )
}
