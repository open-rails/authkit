// Regenerates src/client/generated from this AuthKit checkout.
import { execFileSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

import { startPostgres, stopPostgres } from "../support/postgres.mjs"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")
const pg = await startPostgres()
try {
  execFileSync(
    "go",
    ["run", "./cmd/contract", "-out", path.join(root, "src/client/generated")],
    {
      cwd: path.join(root, "e2e/server"),
      env: { ...process.env, GOWORK: "off", DATABASE_URL: pg.dsn },
      stdio: "inherit",
    }
  )
} finally {
  stopPostgres(pg.name)
}
