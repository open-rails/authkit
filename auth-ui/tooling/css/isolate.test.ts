import { describe, expect, it } from "vitest"

import { isolateCss } from "./isolate"
import { renderStyleInstaller } from "./vite-plugin"

describe("auth-ui CSS isolation", () => {
  it("removes layers and scopes every selector", async () => {
    const css = await isolateCss(`
      @layer theme, utilities;
      @layer theme { :root, :host { --spacing: .25rem; } }
      @layer utilities {
        .hidden { display: none; }
        .authui { color: black; }
        *, ::before { box-sizing: border-box; }
      }
    `)
    expect(css).not.toContain("@layer")
    expect(css).toContain(".authui { --spacing: .25rem; }")
    expect(css).toContain(".authui .hidden, .authui.hidden")
    expect(css).toContain(
      ".authui *, .authui, .authui ::before, .authui::before"
    )
    expect(css).not.toMatch(/(^|[},])\s*\.hidden\s*\{/)
  })

  it("namespaces Tailwind variables and every keyframe", async () => {
    const css = await isolateCss(`
      @property --tw-duration { syntax: "*"; inherits: false; }
      @keyframes spin { to { transform: rotate(360deg); } }
      @keyframes caret-blink { 50% { opacity: 0; } }
      .a { --tw-duration: 1s; animation: spin var(--tw-duration); }
      .b { --animate-caret-blink: caret-blink 1s infinite; }
      .c { animation-name: spinner; }
    `)
    expect(css).toContain("@property --authui-tw-duration")
    expect(css).toContain("@keyframes authui-spin")
    expect(css).toContain("@keyframes authui-caret-blink")
    expect(css).toContain("animation: authui-spin var(--authui-tw-duration)")
    expect(css).toContain("--animate-caret-blink: authui-caret-blink 1s")
    expect(css).toContain("animation-name: spinner")
  })

  it("renders an idempotent style installer", () => {
    const installer = renderStyleInstaller(".authui{display:block}")
    expect(installer).toContain('typeof document !== "undefined"')
    expect(installer).toContain("openrails-auth-ui-styles")
  })
})
