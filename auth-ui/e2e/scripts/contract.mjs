// Regenerates src/client/generated (and api/openapi.json) from this AuthKit
// checkout's route and error catalogs.
import { execFileSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")
execFileSync("go", ["generate", "./internal/httpapi"], {
  cwd: path.resolve(root, ".."),
  env: { ...process.env, GOWORK: "off" },
  stdio: "inherit",
})
