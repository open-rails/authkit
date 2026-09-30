// AuthKit's iam.Perm.Matches: `<persona>:*` covers every permission of the
// persona; any other pattern needs as many segments, each `*` or equal
// (`org:members:*`, `org:*:read`). The persona is always literal, so a bare `*`
// matches nothing, and malformed text never matches. AuthKit's
// iam/testdata/perm_vectors.json pins both matchers.
const SEGMENT = /^[a-z][a-z0-9-]*$/

const segments = (text: string): string[] | null => {
  const segs = text.split(":")
  if (segs.length < 2 || !SEGMENT.test(segs[0])) return null
  return segs.slice(1).every((s) => s === "*" || SEGMENT.test(s)) ? segs : null
}

export function permMatches(grant: string, required: string): boolean {
  const g = segments(grant)
  const c = segments(required)
  if (!g || !c || g[0] !== c[0]) return false
  if (g.length === 2 && g[1] === "*") return true
  return g.length === c.length && g.every((s, i) => s === "*" || s === c[i])
}

export const hasPermission = (
  grants: readonly string[] | undefined,
  required: string
): boolean => !!grants && grants.some((grant) => permMatches(grant, required))
