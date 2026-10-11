import { readAuthKitError } from "../client/errors.ts"
import type {
  APIKey,
  APIKeyCreated,
  GroupMember,
  GroupRole,
  Invitation,
  InvitationCreated,
  ListPage,
  NewOAuthClient,
  OAuthClient,
  OAuthClientCreated,
  OAuthClientSecret,
  OAuthClientUpdate,
  PermissionSet,
  RemoteApplication,
  RemoteApplicationKey,
} from "../client/generated/wire.ts"

// Anything that sends the signed-in person's AuthKit credentials: auth-ui's
// AuthClient or IssuerClient, or a host's own fetch wrapper.
export type AdminAuth = {
  authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
}

export type AdminClientOptions = {
  auth: AdminAuth
  // AuthKit's JSON API mount. Default "/api/v1".
  baseUrl?: string
  // Sent as ?lang= for AuthKit's own messages.
  language?: string
}

export type Page = { cursor?: string; limit?: number }

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE"

// The AuthKit route of each call, beneath the API mount; a contract test
// holds them to the generated route catalog.
export const ADMIN_ROUTES = {
  permissions: ["GET", "/me/permissions"],
  listMembers: ["GET", "/groups/{group_id}/members"],
  setMemberRole: ["PUT", "/groups/{group_id}/members/users/{id}"],
  removeMember: ["DELETE", "/groups/{group_id}/members/users/{id}"],
  listInvitations: ["GET", "/groups/{group_id}/invitations"],
  createInvitation: ["POST", "/groups/{group_id}/invitations"],
  revokeInvitation: ["DELETE", "/groups/{group_id}/invitations/{id}"],
  listRoles: ["GET", "/groups/{group_id}/roles"],
  getRole: ["GET", "/groups/{group_id}/roles/{role}"],
  createRole: ["POST", "/groups/{group_id}/roles"],
  updateRole: ["PATCH", "/groups/{group_id}/roles/{role}"],
  deleteRole: ["DELETE", "/groups/{group_id}/roles/{role}"],
  listAPIKeys: ["GET", "/groups/{group_id}/api-keys"],
  createAPIKey: ["POST", "/groups/{group_id}/api-keys"],
  revokeAPIKey: ["DELETE", "/groups/{group_id}/api-keys/{id}"],
  listOAuthClients: ["GET", "/groups/{group_id}/oauth-clients"],
  getOAuthClient: ["GET", "/groups/{group_id}/oauth-clients/{client_id}"],
  createOAuthClient: ["POST", "/groups/{group_id}/oauth-clients"],
  updateOAuthClient: ["PATCH", "/groups/{group_id}/oauth-clients/{client_id}"],
  rotateOAuthClientSecret: [
    "POST",
    "/groups/{group_id}/oauth-clients/{client_id}/secret",
  ],
  deleteOAuthClient: ["DELETE", "/groups/{group_id}/oauth-clients/{client_id}"],
  listRemoteApplications: ["GET", "/groups/{group_id}/remote-applications"],
  createRemoteApplication: ["POST", "/groups/{group_id}/remote-applications"],
  updateRemoteApplication: [
    "PATCH",
    "/groups/{group_id}/remote-applications/{id}",
  ],
  deleteRemoteApplication: [
    "DELETE",
    "/groups/{group_id}/remote-applications/{id}",
  ],
} as const satisfies Record<string, readonly [Method, string]>

export type AdminRoute = keyof typeof ADMIN_ROUTES

type Query = Record<string, string | number | readonly string[] | undefined>

type CallOptions = {
  params?: Record<string, string>
  query?: Query
  body?: unknown
  signal?: AbortSignal
}

// At most this many pages are read where a list is read whole.
const MAX_PAGES = 50

export type AdminClient = ReturnType<typeof createAdminClient>

// AuthKit's group-administration routes, called with the person's own
// credentials: no host proxy. Errors are AuthKitError.
export function createAdminClient(options: AdminClientOptions) {
  const base = (options.baseUrl ?? "/api/v1").replace(/\/+$/, "")

  async function send(
    route: AdminRoute,
    opts: CallOptions = {}
  ): Promise<{ status: number; body: unknown }> {
    const [method, template] = ADMIN_ROUTES[route]
    const path = template.replace(/\{(\w+)\}/g, (_, name: string) => {
      const value = opts.params?.[name]
      if (!value) throw new Error(`auth-ui admin: ${route} needs ${name}`)
      return encodeURIComponent(value)
    })
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined || v === "") continue
      for (const item of Array.isArray(v) ? v : [v]) qs.append(k, String(item))
    }
    if (options.language && !qs.has("lang")) qs.set("lang", options.language)
    const headers: Record<string, string> = { Accept: "application/json" }
    if (opts.body !== undefined) headers["Content-Type"] = "application/json"
    const res = await options.auth.authFetch(
      `${base}${path}${qs.size ? `?${qs}` : ""}`,
      {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: opts.signal,
        credentials: "same-origin",
      }
    )
    if (!res.ok) throw await readAuthKitError(res)
    const text = res.status === 204 ? "" : await res.text()
    return { status: res.status, body: text ? JSON.parse(text) : undefined }
  }

  const call = async <T>(route: AdminRoute, opts?: CallOptions) =>
    (await send(route, opts)).body as T

  async function all<T>(
    route: AdminRoute,
    opts: CallOptions = {}
  ): Promise<T[]> {
    const out: T[] = []
    let cursor: string | undefined
    for (let i = 0; i < MAX_PAGES; i++) {
      const page = await call<ListPage<T>>(route, {
        ...opts,
        query: { ...opts.query, cursor },
      })
      out.push(...page.data)
      if (!page.next_cursor) break
      cursor = page.next_cursor
    }
    return out
  }

  const g = (group: string, more: Record<string, string> = {}) => ({
    group_id: group,
    ...more,
  })
  const page = (p: Page = {}) => ({ cursor: p.cursor, limit: p.limit })

  return {
    // The caller's role and permissions in group ("root" for root).
    permissions: (group: string, signal?: AbortSignal) =>
      call<PermissionSet>("permissions", {
        query: { group_id: group },
        signal,
      }),

    // User members with their public profiles; role filters (repeatable).
    listMembers: (
      group: string,
      p: Page & { role?: readonly string[] } = {},
      signal?: AbortSignal
    ) =>
      call<ListPage<GroupMember>>("listMembers", {
        params: g(group),
        query: { ...page(p), kind: "user", expand: "user", role: p.role },
        signal,
      }),
    // Gives the user role, replacing the one they hold.
    setMemberRole: (group: string, userId: string, role: string) =>
      call<GroupMember>("setMemberRole", {
        params: g(group, { id: userId }),
        body: { role },
      }),
    removeMember: (group: string, userId: string) =>
      call<void>("removeMember", { params: g(group, { id: userId }) }),

    listInvitations: (group: string, p?: Page, signal?: AbortSignal) =>
      call<ListPage<Invitation>>("listInvitations", {
        params: g(group),
        query: page(p),
        signal,
      }),
    // A link (no email) answers its code and URL once; an emailed
    // invitation answers null, whoever holds the address.
    createInvitation: async (
      group: string,
      input: { role?: string; email?: string; expiresAt?: string | null }
    ): Promise<InvitationCreated | null> => {
      const res = await send("createInvitation", {
        params: g(group),
        body: {
          role: input.role || undefined,
          email: input.email || undefined,
          expires_at: input.expiresAt ?? undefined,
        },
      })
      return res.status === 201 ? (res.body as InvitationCreated) : null
    },
    revokeInvitation: (group: string, id: string) =>
      call<void>("revokeInvitation", { params: g(group, { id }) }),

    // Every role the group can assign: declared, then custom.
    listRoles: (group: string, signal?: AbortSignal) =>
      all<GroupRole>("listRoles", { params: g(group), signal }),
    getRole: (group: string, role: string, signal?: AbortSignal) =>
      call<GroupRole>("getRole", { params: g(group, { role }), signal }),
    // name is bare ("storefront"); the role is <persona>:custom-<name>.
    createRole: (
      group: string,
      input: { name: string; permissions: readonly string[] }
    ) =>
      call<GroupRole>("createRole", {
        params: g(group),
        body: { name: input.name, permissions: input.permissions },
      }),
    updateRole: (group: string, role: string, permissions: readonly string[]) =>
      call<GroupRole>("updateRole", {
        params: g(group, { role }),
        body: { permissions },
      }),
    deleteRole: (group: string, role: string) =>
      call<void>("deleteRole", { params: g(group, { role }) }),

    listAPIKeys: (group: string, p?: Page, signal?: AbortSignal) =>
      call<ListPage<APIKey>>("listAPIKeys", {
        params: g(group),
        query: page(p),
        signal,
      }),
    // The secret is in the answer only.
    createAPIKey: (
      group: string,
      input: { name: string; role: string; expiresAt?: string | null }
    ) =>
      call<APIKeyCreated>("createAPIKey", {
        params: g(group),
        body: {
          name: input.name,
          role: input.role,
          expires_at: input.expiresAt ?? undefined,
        },
      }),
    revokeAPIKey: (group: string, id: string) =>
      call<void>("revokeAPIKey", { params: g(group, { id }) }),

    listOAuthClients: (group: string, signal?: AbortSignal) =>
      all<OAuthClient>("listOAuthClients", { params: g(group), signal }),
    getOAuthClient: (group: string, clientId: string, signal?: AbortSignal) =>
      call<OAuthClient>("getOAuthClient", {
        params: g(group, { client_id: clientId }),
        signal,
      }),
    // A confidential client's secret is in the answer only.
    createOAuthClient: (group: string, input: NewOAuthClient) =>
      call<OAuthClientCreated>("createOAuthClient", {
        params: g(group),
        body: input,
      }),
    updateOAuthClient: (
      group: string,
      clientId: string,
      input: OAuthClientUpdate
    ) =>
      call<OAuthClient>("updateOAuthClient", {
        params: g(group, { client_id: clientId }),
        body: input,
      }),
    rotateOAuthClientSecret: (group: string, clientId: string) =>
      call<OAuthClientSecret>("rotateOAuthClientSecret", {
        params: g(group, { client_id: clientId }),
      }),
    deleteOAuthClient: (group: string, clientId: string) =>
      call<void>("deleteOAuthClient", {
        params: g(group, { client_id: clientId }),
      }),

    // A backend's signing keys for RFC 7523 assertions.
    listRemoteApplications: (group: string, p?: Page, signal?: AbortSignal) =>
      call<ListPage<RemoteApplication>>("listRemoteApplications", {
        params: g(group),
        query: page(p),
        signal,
      }),
    // One trust source: a JWKS URL, or static keys each with a kid.
    createRemoteApplication: (
      group: string,
      input: {
        issuer: string
        jwksUri?: string
        publicKeys?: RemoteApplicationKey[]
        enabled?: boolean
      }
    ) =>
      call<RemoteApplication>("createRemoteApplication", {
        params: g(group),
        body: {
          issuer: input.issuer,
          jwks_uri: input.jwksUri,
          public_keys: input.publicKeys,
          enabled: input.enabled,
        },
      }),
    // A JWKS URL or keys replace the trust source; what is not named stays.
    updateRemoteApplication: (
      group: string,
      id: string,
      input: {
        jwksUri?: string
        publicKeys?: RemoteApplicationKey[]
        enabled?: boolean
      }
    ) =>
      call<RemoteApplication>("updateRemoteApplication", {
        params: g(group, { id }),
        body: {
          jwks_uri: input.jwksUri,
          public_keys: input.publicKeys,
          enabled: input.enabled,
        },
      }),
    deleteRemoteApplication: (group: string, id: string) =>
      call<void>("deleteRemoteApplication", { params: g(group, { id }) }),
  }
}
