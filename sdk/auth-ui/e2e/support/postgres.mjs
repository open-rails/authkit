// Disposable Postgres in Docker. AuthKit needs PostgreSQL 18+ (uuidv7).
import { execFileSync } from "node:child_process"

const IMAGE = process.env.E2E_POSTGRES_IMAGE ?? "postgres:18-alpine"

export async function startPostgres() {
  const name = `auth-ui-e2e-pg-${process.pid}-${Date.now()}`
  execFileSync(
    "docker",
    [
      "run",
      "-d",
      "--rm",
      "--name",
      name,
      "-e",
      "POSTGRES_PASSWORD=postgres",
      "-e",
      "POSTGRES_DB=authkit",
      "-p",
      "127.0.0.1::5432",
      IMAGE,
    ],
    { stdio: ["ignore", "ignore", "inherit"] }
  )
  try {
    const port = execFileSync("docker", ["port", name, "5432/tcp"], {
      encoding: "utf8",
    })
      .trim()
      .split("\n")[0]
      .split(":")
      .pop()
    await waitReady(name)
    return {
      name,
      dsn: `postgres://postgres:postgres@127.0.0.1:${port}/authkit?sslmode=disable`,
    }
  } catch (err) {
    stopPostgres(name)
    throw err
  }
}

export function stopPostgres(name) {
  if (!name) return
  try {
    execFileSync("docker", ["rm", "-f", name], { stdio: "ignore" })
  } catch {
    // already gone
  }
}

async function waitReady(name) {
  const deadline = Date.now() + 60_000
  while (Date.now() < deadline) {
    try {
      // -h forces TCP so the init-time unix-socket server doesn't count as ready.
      execFileSync(
        "docker",
        [
          "exec",
          name,
          "pg_isready",
          "-h",
          "127.0.0.1",
          "-U",
          "postgres",
          "-d",
          "authkit",
        ],
        { stdio: "ignore" }
      )
      return
    } catch {
      await new Promise((r) => setTimeout(r, 500))
    }
  }
  throw new Error(`postgres container ${name} not ready`)
}
