import path from "node:path"
import { fileURLToPath } from "node:url"

import { configDefaults, defineConfig } from "vitest/config"

const root = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  resolve: {
    alias: { "#authui": path.resolve(root, "src") },
  },
  test: {
    environment: "node",
    exclude: [...configDefaults.exclude, "e2e/**"],
    restoreMocks: true,
  },
})
