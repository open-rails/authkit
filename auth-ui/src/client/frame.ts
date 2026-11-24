// Whether this page is framed by a page of another origin.
export function inCrossOriginFrame(): boolean {
  if (typeof window === "undefined" || window.top === window.self) return false
  try {
    return window.top?.location.origin !== window.location.origin
  } catch {
    return true
  }
}
