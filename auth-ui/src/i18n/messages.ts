import { en } from "../locales/en.ts"

type Widen<T> = {
  [K in keyof T]: T[K] extends string ? string : Widen<T[K]>
}

/** The complete message tree; English is the reference shape. */
export type AuthUiMessages = Widen<typeof en>

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends string ? string : DeepPartial<T[K]>
}

/** A locale bundle or host override: any subset of the tree. */
export type AuthUiMessageBundle = DeepPartial<AuthUiMessages>

type Paths<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string
    ? `${P}${K}`
    : Paths<T[K], `${P}${K}.`>
}[keyof T & string]

/** Dotted key of any message, e.g. `signIn.title`. */
export type MessageKey = Paths<AuthUiMessages>

export type MessageVars = Record<string, string | number>

/**
 * Host translation hook. Receives the bare key (`signIn.title`,
 * `errors.rate_limited`); return nothing or the key itself to use ours.
 */
export type AuthUiTranslate = (
  key: string,
  vars?: MessageVars
) => string | null | undefined

/** Types a locale bundle or override against the message tree. */
export function defineMessages(
  bundle: AuthUiMessageBundle
): AuthUiMessageBundle {
  return bundle
}

export const defaultMessages: AuthUiMessages = en

type Tree = { [key: string]: string | Tree }

function mergeInto(target: Tree, source: Tree): Tree {
  const out: Tree = { ...target }
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined || value === null) continue
    const current = out[key]
    if (typeof value === "string") {
      if (value !== "") out[key] = value
    } else if (typeof current === "object") {
      out[key] = mergeInto(current, value)
    } else {
      out[key] = mergeInto({}, value)
    }
  }
  return out
}

/** Layers bundles over English; later bundles win, missing keys fall back. */
export function resolveMessages(
  bundles?: AuthUiMessageBundle | readonly AuthUiMessageBundle[]
): AuthUiMessages {
  const list = bundles ? (Array.isArray(bundles) ? bundles : [bundles]) : []
  let tree = en as unknown as Tree
  for (const bundle of list) tree = mergeInto(tree, bundle as Tree)
  return tree as unknown as AuthUiMessages
}

export function interpolate(template: string, vars?: MessageVars): string {
  if (!vars) return template
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in vars ? String(vars[name]) : match
  )
}

function lookup(messages: AuthUiMessages, key: string): string | undefined {
  let node: unknown = messages
  for (const part of key.split(".")) {
    if (!node || typeof node !== "object") return undefined
    node = (node as Tree)[part]
  }
  return typeof node === "string" ? node : undefined
}

export interface Translator {
  messages: AuthUiMessages
  t(key: MessageKey, vars?: MessageVars): string
  /** Message for an AuthKit error, error code, or thrown value. */
  error(error: unknown, vars?: MessageVars): string
}

function errorCode(error: unknown): string | undefined {
  if (typeof error === "string") return error
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code: unknown }).code
    if (typeof code === "string") return code
  }
  return undefined
}

function isNetworkError(error: unknown): boolean {
  return error instanceof TypeError && /fetch|network/i.test(error.message)
}

export function createTranslator(
  messages: AuthUiMessages,
  hostT?: AuthUiTranslate
): Translator {
  const translate = (key: string, vars?: MessageVars): string | undefined => {
    const hosted = hostT?.(key, vars)
    if (hosted && hosted !== key) return hosted
    const own = lookup(messages, key)
    return own === undefined ? undefined : interpolate(own, vars)
  }
  return {
    messages,
    t: (key, vars) => translate(key, vars) ?? key,
    error(error, vars) {
      const code = errorCode(error)
      if (code && code !== "generic" && code !== "network") {
        const metadata =
          error && typeof error === "object" && "metadata" in error
            ? (error as { metadata?: MessageVars }).metadata
            : undefined
        const message = translate(`errors.${code}`, { ...metadata, ...vars })
        if (message) return message
      }
      const fallback = isNetworkError(error)
        ? "errors.network"
        : "errors.generic"
      return translate(fallback, vars) ?? messages.errors.generic
    },
  }
}
