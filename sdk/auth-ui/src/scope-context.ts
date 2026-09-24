import { createContext, useContext, type CSSProperties } from "react"

import {
  appearanceStyle,
  appearanceTheme,
  type AuthUiAppearance,
  type AuthUiTheme,
} from "./appearance.ts"

export const AppearanceContext = createContext<AuthUiAppearance | undefined>(
  undefined
)

export interface ScopeProps {
  className: string
  "data-authui-theme": AuthUiTheme
  style?: CSSProperties
}

/** Props that make an element a styling root; portals carry them too. */
export function useScopeProps(): ScopeProps {
  const appearance = useContext(AppearanceContext)
  return {
    className: "authui",
    "data-authui-theme": appearanceTheme(appearance),
    style: appearanceStyle(appearance),
  }
}
