/** A date and time in the reader's language, or the browser's for a tag it can't read. */
export const dateTime = (
  value: string | null | undefined,
  language?: string
) => {
  if (!value) return ""
  const date = new Date(value)
  const style = { dateStyle: "medium", timeStyle: "short" } as const
  try {
    return date.toLocaleString(language, style)
  } catch {
    return date.toLocaleString(undefined, style)
  }
}

/** A user agent as its browser and operating system, or null when unknown. */
export const browserAndOS = (ua: string | null | undefined) => {
  // Automation keeps its full user agent in view.
  if (!ua || /HeadlessChrome/.test(ua)) return null
  const browser = /Edg\/|EdgiOS\//.test(ua)
    ? "Edge"
    : /OPR\//.test(ua)
      ? "Opera"
      : /Firefox\/|FxiOS\//.test(ua)
        ? "Firefox"
        : /Chrome\/|CriOS\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : null
  const os = /iPhone|iPad|iPod/.test(ua)
    ? "iOS"
    : /Android/.test(ua)
      ? "Android"
      : /Windows/.test(ua)
        ? "Windows"
        : /Mac OS X|Macintosh/.test(ua)
          ? "macOS"
          : /Linux|X11/.test(ua)
            ? "Linux"
            : null
  return browser && os ? { browser, os } : null
}

/** A language tag by its name in the reader's language, or the tag itself. */
export const languageName = (
  tag: string | null | undefined,
  language?: string
) => {
  if (!tag) return ""
  try {
    return new Intl.DisplayNames(language, { type: "language" }).of(tag) ?? tag
  } catch {
    return tag
  }
}
