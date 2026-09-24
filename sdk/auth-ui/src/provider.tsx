import { useMemo, type ReactNode } from "react"

import type { AuthUiAppearance } from "./appearance.ts"
import { MessagesContext } from "./i18n/context.ts"
import {
  createTranslator,
  resolveMessages,
  type AuthUiMessageBundle,
  type AuthUiTranslate,
} from "./i18n/messages.ts"
import { AppearanceContext } from "./scope-context.ts"

export interface AuthUiProviderProps {
  appearance?: AuthUiAppearance
  /** Locale bundle(s) layered over English; later entries win. */
  messages?: AuthUiMessageBundle | readonly AuthUiMessageBundle[]
  /** Host translation hook, consulted before the bundles. */
  t?: AuthUiTranslate
  children?: ReactNode
}

/** Renders no DOM; surfaces create their own styling roots. */
export function AuthUiProvider({
  appearance,
  messages,
  t,
  children,
}: AuthUiProviderProps) {
  const translator = useMemo(
    () => createTranslator(resolveMessages(messages), t),
    [messages, t]
  )
  return (
    <AppearanceContext.Provider value={appearance}>
      <MessagesContext.Provider value={translator}>
        {children}
      </MessagesContext.Provider>
    </AppearanceContext.Provider>
  )
}
