import { createContext, useContext } from "react"

import {
  createTranslator,
  defaultMessages,
  type Translator,
} from "./messages.ts"

export const MessagesContext = createContext<Translator>(
  createTranslator(defaultMessages)
)

/** English defaults when rendered outside an `AuthUiProvider`. */
export function useMessages(): Translator {
  return useContext(MessagesContext)
}
