// Mirrors authhttp sanitizeReturnTo: only an app-relative path survives.
export function safeReturnTo(
  value: string | null | undefined,
  origin?: string
): string | null {
  const raw = value?.trim()
  if (!raw) return null
  const base = origin ?? globalThis.location?.origin ?? "http://localhost"
  try {
    const url = new URL(raw, base)
    if (url.origin !== new URL(base).origin) return null
    if (/[\\\r\n\t]/.test(raw)) return null
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return null
  }
}
