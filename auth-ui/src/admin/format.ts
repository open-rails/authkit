export const dateTime = (
  value: string | null | undefined,
  language?: string
) =>
  value
    ? new Date(value).toLocaleString(language, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : ""

/** A user agent as its browser and operating system, or null when unknown. */
export const browserAndOS = (ua: string | null | undefined) => {
  if (!ua) return null
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /OPR\//.test(ua)
      ? "Opera"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
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
