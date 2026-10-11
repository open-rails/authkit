import { useMemo } from "react"

import { useMessages } from "../i18n/context.ts"
import {
  createTranslator,
  resolveMessages,
  type AuthUiMessageBundle,
  type MessageKey,
  type MessageVars,
  type Translator,
} from "../i18n/messages.ts"
import { de as mainDe } from "../locales/de.ts"
import { es as mainEs } from "../locales/es.ts"
import { ja as mainJa } from "../locales/ja.ts"
import { ko as mainKo } from "../locales/ko.ts"
import { zh as mainZh } from "../locales/zh.ts"
import { de } from "./locales/de.ts"
import { en } from "./locales/en.ts"
import { es } from "./locales/es.ts"
import { ja } from "./locales/ja.ts"
import { ko } from "./locales/ko.ts"
import { zh } from "./locales/zh.ts"

type Widen<T> = {
  [K in keyof T]: T[K] extends string ? string : Widen<T[K]>
}
type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends string ? string : DeepPartial<T[K]>
}
type Paths<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string
    ? `${P}${K}`
    : Paths<T[K], `${P}${K}.`>
}[keyof T & string]

/** The admin components' words; English is the reference shape. */
export type AdminMessageTree = Widen<typeof en>
export type AdminMessageKey = Paths<AdminMessageTree>

/**
 * Overrides for the admin components: their own words under `admin`, and
 * any of auth-ui's (`errors`, `common`, …).
 */
export type AdminMessageBundle = AuthUiMessageBundle & {
  admin?: DeepPartial<AdminMessageTree>
}

const LOCALES: Record<string, [AuthUiMessageBundle, AdminMessageTree]> = {
  en: [{}, en],
  de: [mainDe, de],
  es: [mainEs, es],
  ja: [mainJa, ja],
  ko: [mainKo, ko],
  zh: [mainZh, zh],
}

/** The languages the admin components ship words for. */
export const ADMIN_LANGUAGES = Object.keys(LOCALES)

const pick = (language?: string) =>
  language ? LOCALES[language.toLowerCase().split(/[-_]/)[0]] : undefined

// auth-ui's words (the language's bundle, else the surrounding provider's)
// with the admin tree under `admin`, then the host's overrides.
export function useAdminTranslator(
  language?: string,
  messages?: AdminMessageBundle | readonly AdminMessageBundle[]
): Translator {
  const host = useMessages()
  return useMemo(() => {
    const locale = pick(language)
    const overrides = messages
      ? Array.isArray(messages)
        ? messages
        : [messages as AdminMessageBundle]
      : []
    const bundles = [
      locale ? locale[0] : host.messages,
      { admin: en },
      locale ? { admin: locale[1] } : {},
      ...overrides,
    ] as AuthUiMessageBundle[]
    return createTranslator(resolveMessages(bundles))
  }, [host, language, messages])
}

export type AdminTranslator = {
  t(key: AdminMessageKey, vars?: MessageVars): string
  error(error: unknown, vars?: MessageVars): string
}

export function useAdminMessages(): AdminTranslator {
  const translator = useMessages()
  return useMemo(
    () => ({
      t: (key, vars) => translator.t(`admin.${key}` as MessageKey, vars),
      error: translator.error,
    }),
    [translator]
  )
}
