import fs from "node:fs"
const manifest = JSON.parse(
  fs.readFileSync(new URL("./coverage.json", import.meta.url), "utf8")
)
const report = JSON.parse(
  fs.readFileSync(
    new URL("../test-results/critical.json", import.meta.url),
    "utf8"
  )
)
const methods = new Set(),
  cases = new Set(),
  executableCases = new Map(),
  failures = []
let count = 0
function walk(suite) {
  for (const child of suite.suites ?? []) walk(child)
  for (const spec of suite.specs ?? [])
    for (const test of spec.tests ?? []) {
      count++
      const ids = spec.title.match(/\bAK-UI-\d{2}\b/g) ?? []
      if (ids.length !== 1)
        failures.push(`Missing or ambiguous case ID: ${spec.title}`)
      else executableCases.set(ids[0], (executableCases.get(ids[0]) ?? 0) + 1)
      if (
        test.expectedStatus !== "passed" ||
        !test.results?.length ||
        test.results.some((r) => r.status !== "passed")
      ) {
        failures.push(spec.title)
        continue
      }
      for (const id of spec.title.match(/AK-J29-C\d{2}/g) ?? []) cases.add(id)
      for (const result of test.results)
        for (const attachment of result.attachments ?? []) {
          if (attachment.name !== "public-client-invocations") continue
          const body = attachment.body
            ? Buffer.from(attachment.body, "base64").toString()
            : fs.readFileSync(attachment.path, "utf8")
          for (const method of JSON.parse(body).methods) methods.add(method)
        }
    }
}
for (const suite of report.suites ?? []) walk(suite)
for (const error of report.errors ?? [])
  failures.push(error.message ?? String(error))
const requiredExecutableCases = new Set(manifest.requiredExecutableCaseIDs)
if (requiredExecutableCases.size !== manifest.requiredExecutableCaseIDs.length)
  failures.push("Duplicate executable case ID in manifest")
const missingExecutableCases = [...requiredExecutableCases].filter(
  (id) => !executableCases.has(id)
)
const unexpectedExecutableCases = [...executableCases.keys()].filter(
  (id) => !requiredExecutableCases.has(id)
)
const duplicateExecutableCases = [...executableCases]
  .filter(([, n]) => n !== 1)
  .map(([id]) => id)
const missingCases = manifest.requiredScenarioIDs.filter((x) => !cases.has(x))
const missingMethods = manifest.requiredClientMethods.filter(
  (x) => !methods.has(x)
)
const outcome = {
  tests: count,
  executableCases: [...executableCases.keys()].sort(),
  scenarios: [...cases].sort(),
  methods: [...methods].sort(),
  failures,
  missingCases,
  missingMethods,
  missingExecutableCases,
  unexpectedExecutableCases,
  duplicateExecutableCases,
}
fs.writeFileSync(
  new URL("../test-results/critical-coverage.json", import.meta.url),
  JSON.stringify(outcome, null, 2) + "\n"
)
if (
  !count ||
  failures.length ||
  missingCases.length ||
  missingMethods.length ||
  missingExecutableCases.length ||
  unexpectedExecutableCases.length ||
  duplicateExecutableCases.length
) {
  console.error(
    JSON.stringify(
      {
        tests: count,
        failures,
        missingCases,
        missingMethods,
        missingExecutableCases,
        unexpectedExecutableCases,
        duplicateExecutableCases,
      },
      null,
      2
    )
  )
  process.exit(1)
}
console.log(
  `${count} real-service browser/client cases passed; ${cases.size} required scenario IDs and all ${manifest.requiredClientMethods.length} selected client methods observed. No skips accepted.`
)
