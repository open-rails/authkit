import postcss, { type Plugin, type Rule } from "postcss"

export const SCOPE_CLASS = "authui"
const ROOT = `.${SCOPE_CLASS}`
const PREFIX = `${SCOPE_CLASS}-`

// Host layers could outrank our selectors regardless of specificity.
function removeCascadeLayers(): Plugin {
  return {
    postcssPlugin: "authui-remove-layers",
    Once(root) {
      root.walkAtRules("layer", (rule) => {
        if (rule.nodes) rule.replaceWith(...rule.nodes)
        else rule.remove()
      })
    },
  }
}

function isKeyframeStep(rule: Rule): boolean {
  const parent = rule.parent
  return parent?.type === "atrule" && /keyframes$/i.test(parent.name)
}

function alreadyScoped(selector: string): boolean {
  return (
    selector === ROOT ||
    [".", "[", ":", " ", "-"].some((c) => selector.startsWith(ROOT + c))
  )
}

function sameElementSelector(selector: string): string | undefined {
  if (selector === "*") return ROOT
  if (selector.startsWith("*:")) return ROOT + selector.slice(1)
  if (selector.startsWith(".") || selector.startsWith("[")) {
    return ROOT + selector
  }
  if (/^::?(before|after|backdrop)$/.test(selector)) return ROOT + selector
  return undefined
}

function scopeSelectors(): Plugin {
  return {
    postcssPlugin: "authui-scope-selectors",
    Once(root) {
      root.walkRules((rule) => {
        if (isKeyframeStep(rule)) return
        const scoped = rule.selectors.flatMap((selector) => {
          if ([":root", ":host", "html", "body"].includes(selector)) {
            return [ROOT]
          }
          if (alreadyScoped(selector)) return [selector]
          const out = [`${ROOT} ${selector}`]
          const same = sameElementSelector(selector)
          if (same) out.push(same)
          return out
        })
        rule.selectors = [...new Set(scoped)]
      })
    },
  }
}

function namespaceInternals(): Plugin {
  return {
    postcssPlugin: "authui-namespace-internals",
    Once(root) {
      const keyframes = new Set<string>()
      root.walkAtRules(/keyframes$/i, (rule) => {
        if (!rule.params.startsWith(PREFIX)) keyframes.add(rule.params)
      })
      const names = [...keyframes].map((n) => n.replace(/[-]/g, "\\-"))
      const keyframeRef = names.length
        ? new RegExp(`(?<![\\w-])(${names.join("|")})(?![\\w-])`, "g")
        : undefined

      root.walkAtRules((rule) => {
        if (/keyframes$/i.test(rule.name) && keyframes.has(rule.params)) {
          rule.params = PREFIX + rule.params
        }
        rule.params = rule.params.replaceAll("--tw-", `--${PREFIX}tw-`)
      })
      root.walkDecls((decl) => {
        decl.prop = decl.prop.replaceAll("--tw-", `--${PREFIX}tw-`)
        decl.value = decl.value.replaceAll("--tw-", `--${PREFIX}tw-`)
        if (keyframeRef && /^(animation|animation-name|--)/.test(decl.prop)) {
          decl.value = decl.value.replace(keyframeRef, `${PREFIX}$1`)
        }
      })
    },
  }
}

/**
 * Turns Tailwind's global output into auth-ui-owned CSS: layers removed,
 * every selector scoped under `.authui`, Tailwind variables and keyframes
 * namespaced, so neither the host nor the library can style the other.
 */
export async function isolateCss(css: string): Promise<string> {
  const result = await postcss([
    removeCascadeLayers(),
    scopeSelectors(),
    namespaceInternals(),
  ]).process(css, { from: undefined })
  return result.css
}
