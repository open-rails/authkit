export const CODE_LENGTH = 6

export type Device = {
  browser: string | null
  os: string | null
  mobile: boolean
}

// Coarse, dependency-free UA summary for the sessions list.
export function parseUserAgent(ua: string | undefined): Device {
  const s = ua ?? ""
  const pick = (rules: [RegExp, string][]) =>
    rules.find(([re]) => re.test(s))?.[1] ?? null
  return {
    browser: pick([
      [/Edg\//, "Edge"],
      [/OPR\/|Opera/, "Opera"],
      [/Firefox\//, "Firefox"],
      [/HeadlessChrome/, "Chrome"],
      [/Chrome\/|CriOS/, "Chrome"],
      [/Safari\//, "Safari"],
    ]),
    os: pick([
      [/iPhone|iPad|iPod/, "iOS"],
      [/Android/, "Android"],
      [/Windows/, "Windows"],
      [/Mac OS X|Macintosh/, "macOS"],
      [/CrOS/, "ChromeOS"],
      [/Linux/, "Linux"],
    ]),
    mobile: /Mobi|Android|iPhone|iPad/.test(s),
  }
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["week", 604_800],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
]

export function relativeTime(iso: string, now = Date.now()): string {
  const locale =
    typeof document !== "undefined"
      ? document.documentElement.lang || undefined
      : undefined
  const fmt = new Intl.RelativeTimeFormat(locale, { numeric: "auto" })
  const diff = (new Date(iso).getTime() - now) / 1000
  for (const [unit, secs] of UNITS) {
    if (Math.abs(diff) >= secs) return fmt.format(Math.round(diff / secs), unit)
  }
  return fmt.format(0, "second")
}
