import type { CSSProperties } from "react"

/**
 * `light`/`dark` force a palette, `auto` follows the OS, `inherit` reads the
 * host's shadcn tokens (`--primary`, …) and its `.dark` class.
 */
export type AuthUiTheme = "light" | "dark" | "auto" | "inherit"

/** Raw CSS values applied as `--authui-*` custom properties on every root. */
export interface AuthUiVariables {
  background?: string
  foreground?: string
  card?: string
  cardForeground?: string
  popover?: string
  popoverForeground?: string
  primary?: string
  primaryForeground?: string
  /** Filled-button fill; defaults to `primary` in `inherit` mode. */
  primarySolid?: string
  primarySolidForeground?: string
  secondary?: string
  secondaryForeground?: string
  muted?: string
  mutedForeground?: string
  accent?: string
  accentForeground?: string
  destructive?: string
  success?: string
  border?: string
  input?: string
  ring?: string
  radius?: string
  fontFamily?: string
}

export interface AuthUiAppearance {
  theme?: AuthUiTheme
  variables?: AuthUiVariables
}

const CSS_VARIABLE: Record<keyof AuthUiVariables, string> = {
  background: "--authui-background",
  foreground: "--authui-foreground",
  card: "--authui-card",
  cardForeground: "--authui-card-foreground",
  popover: "--authui-popover",
  popoverForeground: "--authui-popover-foreground",
  primary: "--authui-primary",
  primaryForeground: "--authui-primary-foreground",
  primarySolid: "--authui-primary-solid",
  primarySolidForeground: "--authui-primary-solid-foreground",
  secondary: "--authui-secondary",
  secondaryForeground: "--authui-secondary-foreground",
  muted: "--authui-muted",
  mutedForeground: "--authui-muted-foreground",
  accent: "--authui-accent",
  accentForeground: "--authui-accent-foreground",
  destructive: "--authui-destructive",
  success: "--authui-success",
  border: "--authui-border",
  input: "--authui-input",
  ring: "--authui-ring",
  radius: "--authui-radius",
  fontFamily: "--authui-font",
}

export function appearanceStyle(
  appearance: AuthUiAppearance | undefined
): CSSProperties | undefined {
  const variables = appearance?.variables
  if (!variables) return undefined
  const style: Record<string, string> = {}
  for (const [key, value] of Object.entries(variables)) {
    const prop = CSS_VARIABLE[key as keyof AuthUiVariables]
    if (prop && value) style[prop] = value
  }
  return style as CSSProperties
}

export function appearanceTheme(
  appearance: AuthUiAppearance | undefined
): AuthUiTheme {
  return appearance?.theme ?? "auto"
}
