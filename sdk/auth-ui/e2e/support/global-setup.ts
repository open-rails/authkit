import { execFileSync, spawn, type ChildProcess } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
import path from "node:path"

import { build } from "vite"

import { startPostgres, stopPostgres } from "./postgres.mjs"

const root = path.resolve(import.meta.dirname, "../..")

export default async function globalSetup() {
  const work = mkdtempSync(path.join(tmpdir(), "auth-ui-e2e-"))
  let pg: { name: string; dsn: string } | undefined
  let server: ChildProcess | undefined
  const teardown = async () => {
    if (server && server.exitCode === null) {
      server.kill("SIGTERM")
      await new Promise((r) => server!.once("exit", r))
    }
    stopPostgres(pg?.name)
    rmSync(work, { recursive: true, force: true })
  }
  try {
    await buildReactApp()
    const bin = path.join(work, "authkit-e2e-server")
    execFileSync("go", ["build", "-o", bin, "./cmd/server"], {
      cwd: path.join(root, "e2e/server"),
      env: { ...process.env, GOWORK: "off" },
      stdio: "inherit",
    })
    pg = await startPostgres()
    const port = await freePort()
    const baseURL = `http://localhost:${port}`
    server = spawn(
      bin,
      [
        "-addr",
        `127.0.0.1:${port}`,
        "-base-url",
        baseURL,
        "-static",
        path.join(root, "e2e/fixtures"),
        "-lifetime",
        "30m",
      ],
      {
        env: { ...process.env, DATABASE_URL: pg.dsn },
        stdio: ["ignore", "inherit", "inherit"],
      }
    )
    await waitHealthy(`http://127.0.0.1:${port}/api/v1/capabilities`, server)
    process.env.E2E_BASE_URL = baseURL
    return teardown
  } catch (err) {
    await teardown()
    throw err
  }
}

// Bundles each e2e host app, self-contained, against the built dist/ (run
// `pnpm build` first).
async function buildReactApp() {
  const apps = {
    app: "react-app/main.tsx",
    "sign-in": "sign-in-app/main.tsx",
    solana: "solana-app/main.ts",
  }
  for (const [name, entry] of Object.entries(apps)) {
    await build({
      configFile: false,
      logLevel: "warn",
      root: path.dirname(path.join(root, "e2e", entry)),
      build: {
        outDir: path.join(root, "e2e/.react-app"),
        emptyOutDir: name === "app",
        minify: false,
        rollupOptions: {
          input: path.join(root, "e2e", entry),
          output: { entryFileNames: `${name}.js` },
        },
      },
    })
  }
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.once("error", reject)
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number }
      srv.close(() => resolve(port))
    })
  })
}

async function waitHealthy(url: string, proc: ChildProcess) {
  const deadline = Date.now() + 60_000
  while (Date.now() < deadline) {
    if (proc.exitCode !== null)
      throw new Error(`e2e server exited (${proc.exitCode})`)
    try {
      if ((await fetch(url)).ok) return
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error("e2e server did not become healthy")
}
