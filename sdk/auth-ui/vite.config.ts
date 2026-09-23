import path from "node:path"
import { fileURLToPath } from "node:url"

import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import dts from "vite-plugin-dts"

import { authUiCssPlugin } from "./tooling/css/vite-plugin.ts"

const root = path.dirname(fileURLToPath(import.meta.url))
const src = (p: string) => path.resolve(root, "src", p)

const LOCALES = ["en", "de", "es", "ja", "ko", "zh"]

const EXTERNAL = [
  "react",
  "react-dom",
  "@base-ui/react",
  "@hugeicons/core-free-icons",
  "@hugeicons/react",
  "class-variance-authority",
  "clsx",
  "input-otp",
  "tailwind-merge",
  "@solana/wallet-adapter-react",
]

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    dts({
      include: ["src"],
      entryRoot: "src",
      exclude: [
        "src/**/*.test.ts",
        "src/**/*.test.tsx",
        "src/**/testing.ts",
        "src/test/**",
      ],
      tsconfigPath: path.resolve(root, "tsconfig.json"),
    }),
    authUiCssPlugin({ entries: ["index"] }),
  ],
  resolve: {
    alias: { "#authui": path.resolve(root, "src") },
  },
  build: {
    lib: {
      entry: {
        index: src("index.ts"),
        client: src("client/index.ts"),
        solana: src("solana/index.ts"),
        ...Object.fromEntries(
          LOCALES.map((l) => [`locales/${l}`, src(`locales/${l}.ts`)])
        ),
      },
      formats: ["es"],
      cssFileName: "styles",
    },
    sourcemap: true,
    rollupOptions: {
      external: (id) =>
        EXTERNAL.some((dep) => id === dep || id.startsWith(`${dep}/`)),
    },
  },
})
