import path from "node:path"
import { fileURLToPath } from "node:url"

import { defineConfig } from "vite"
import dts from "vite-plugin-dts"

const root = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [
    dts({
      include: ["src"],
      entryRoot: "src",
      exclude: ["src/**/*.test.ts", "src/**/testing.ts"],
      tsconfigPath: path.resolve(root, "tsconfig.json"),
    }),
  ],
  build: {
    lib: {
      entry: { client: path.resolve(root, "src/client/index.ts") },
      formats: ["es"],
    },
    sourcemap: true,
  },
})
