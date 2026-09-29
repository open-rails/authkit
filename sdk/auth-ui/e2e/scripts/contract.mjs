// Regenerates src/client/generated from this AuthKit checkout.
import { execFileSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

import { startPostgres, stopPostgres } from "../support/postgres.mjs"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")
const generated = path.join(root, "src/client/generated")
execFileSync("go", ["generate", "./internal/errmodel"], {
  cwd: path.resolve(root, "../.."),
  env: { ...process.env, GOWORK: "off" },
  stdio: "inherit",
})
const pg = await startPostgres()
try {
  execFileSync("go", ["run", "./cmd/contract", "-out", generated], {
    cwd: path.join(root, "e2e/server"),
    env: { ...process.env, GOWORK: "off", DATABASE_URL: pg.dsn },
    stdio: "inherit",
  })
} finally {
  stopPostgres(pg.name)
}
