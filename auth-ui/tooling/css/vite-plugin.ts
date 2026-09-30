import type { Plugin } from "vite"

import { isolateCss } from "./isolate.ts"

const STYLE_ELEMENT_ID = "openrails-auth-ui-styles"

// Installing from the entry lets hosts import components alone; the emitted
// stylesheet stays available for SSR or manual loading.
export function renderStyleInstaller(css: string): string {
  return `
const __authuiCss = ${JSON.stringify(css)};
if (typeof document !== "undefined") {
  let __authuiStyle = document.getElementById(${JSON.stringify(STYLE_ELEMENT_ID)});
  if (!__authuiStyle) {
    __authuiStyle = document.createElement("style");
    __authuiStyle.id = ${JSON.stringify(STYLE_ELEMENT_ID)};
    (document.head || document.documentElement).appendChild(__authuiStyle);
  }
  if (__authuiStyle.textContent !== __authuiCss) __authuiStyle.textContent = __authuiCss;
}
`
}

/** Isolates the emitted stylesheet and installs it from the given entries. */
export function authUiCssPlugin(options: { entries: string[] }): Plugin {
  return {
    name: "openrails-auth-ui-css",
    enforce: "post",
    async generateBundle(_options, bundle) {
      const stylesheet = Object.values(bundle).find(
        (item) => item.type === "asset" && item.fileName.endsWith(".css")
      )
      if (!stylesheet || stylesheet.type !== "asset") {
        throw new Error("auth-ui build did not emit a stylesheet")
      }
      const css = await isolateCss(String(stylesheet.source))
      stylesheet.source = css

      for (const item of Object.values(bundle)) {
        if (
          item.type === "chunk" &&
          item.isEntry &&
          options.entries.includes(item.name)
        ) {
          item.code = `${renderStyleInstaller(css)}\n${item.code}`
        }
      }
    },
  }
}
