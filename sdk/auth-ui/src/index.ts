// Styled AuthKit UI. The entry installs its isolated stylesheet once in the
// browser; `./styles.css` is the same sheet for SSR or manual loading.
import "./styles.css"

export { AuthUiProvider, type AuthUiProviderProps } from "./provider.tsx"
export { AuthUiRoot } from "./scope.tsx"
export type {
  AuthUiAppearance,
  AuthUiTheme,
  AuthUiVariables,
} from "./appearance.ts"
export {
  createTranslator,
  defaultMessages,
  defineMessages,
  interpolate,
  resolveMessages,
  useMessages,
  type AuthUiMessageBundle,
  type AuthUiMessages,
  type AuthUiTranslate,
  type MessageKey,
  type MessageVars,
  type Translator,
} from "./i18n/index.ts"
export * from "./components/sign-in/index.ts"
export * from "./components/account/index.ts"
