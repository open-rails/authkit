import { execFileSync, spawn, type ChildProcess } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
import path from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { build } from "vite"

const root = path.resolve(import.meta.dirname, "..")
export default async function setup() {
  const temp = mkdtempSync(path.join(tmpdir(), "authkit-critical-ui-"))
  const container = `authkit-critical-ui-${process.pid}-${Date.now()}`
  let databaseStarted = false
  let processRef: ChildProcess | undefined
  const cleanup = async () => {
    if (processRef && processRef.exitCode === null) {
      const stopped = new Promise<void>((resolve) =>
        processRef!.once("exit", () => resolve())
      )
      processRef.kill("SIGTERM")
      const force = setTimeout(() => processRef!.kill("SIGKILL"), 8_000)
      try {
        await stopped
      } finally {
        clearTimeout(force)
      }
    }
    if (databaseStarted)
      execFileSync("docker", ["rm", "-f", container], { stdio: "ignore" })
    rmSync(temp, { recursive: true, force: true })
  }
  try {
    await build({
      configFile: false,
      logLevel: "warn",
      build: {
        outDir: path.join(root, ".critical-app"),
        emptyOutDir: true,
        minify: false,
        rollupOptions: {
          input: path.join(root, "critical/app/main.tsx"),
          onwarn(warning, warn) {
            if (warning.code !== "MODULE_LEVEL_DIRECTIVE") warn(warning)
          },
          output: { entryFileNames: "app.js" },
        },
      },
    })
    const bin = path.join(temp, "authkit-critical-ui")
    execFileSync("go", ["build", "-p", "2", "-o", bin, "./cmd/server"], {
      cwd: path.join(root, "e2e/server"),
      env: { ...process.env, GOWORK: "off", GOMAXPROCS: "2" },
      stdio: "inherit",
    })
    execFileSync(
      "docker",
      [
        "run",
        "-d",
        "--rm",
        "--name",
        container,
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-e",
        "POSTGRES_DB=critical_ui",
        "-p",
        "127.0.0.1::5432",
        process.env.E2E_POSTGRES_IMAGE ?? "postgres:18-alpine",
      ],
      { stdio: "ignore" }
    )
    databaseStarted = true
    const databasePort = execFileSync(
      "docker",
      ["port", container, "5432/tcp"],
      { encoding: "utf8" }
    )
      .trim()
      .split("\n")[0]
      .split(":")
      .pop()
    const deadline = Date.now() + 90_000
    let ready = false
    while (Date.now() < deadline) {
      try {
        execFileSync(
          "docker",
          [
            "exec",
            container,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "postgres",
            "-d",
            "critical_ui",
          ],
          { stdio: "ignore", timeout: 5000 }
        )
        ready = true
        break
      } catch {
        await delay(250)
      }
    }
    if (!ready)
      throw new Error("owned critical PostgreSQL did not become ready")
    const port = await freePort()
    const origin = `http://127.0.0.1:${port}`
    processRef = spawn(
      bin,
      [
        "-addr",
        `127.0.0.1:${port}`,
        "-origin",
        origin,
        "-dist",
        path.join(root, "dist"),
        "-app",
        path.join(root, ".critical-app"),
      ],
      {
        env: {
          ...process.env,
          DATABASE_URL: `postgres://postgres:postgres@127.0.0.1:${databasePort}/critical_ui?sslmode=disable`,
        },
        stdio: ["ignore", "inherit", "inherit"],
      }
    )
    let serving = false
    const serverDeadline = Date.now() + 60_000
    while (Date.now() < serverDeadline) {
      if (processRef.exitCode !== null)
        throw new Error(`critical server exited: ${processRef.exitCode}`)
      try {
        if ((await fetch(`${origin}/api/v1/capabilities`)).ok) {
          serving = true
          break
        }
      } catch {
        /* startup */
      }
      await delay(100)
    }
    if (!serving) throw new Error("real critical AuthKit did not become ready")
    process.env.E2E_BASE_URL = origin
    return cleanup
  } catch (error) {
    await cleanup()
    throw error
  }
}
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = createServer()
    socket.once("error", reject)
    socket.listen(0, "127.0.0.1", () => {
      const port = (socket.address() as { port: number }).port
      socket.close(() => resolve(port))
    })
  })
}
