// Same glob semantics as AuthKit's PermMatches: a trailing `*` segment covers
// the remainder (`root:*` covers `root:tags:update`); other grants match exactly.
export function permMatches(grant: string, required: string): boolean {
  if (grant === required) return true
  const g = grant.split(":")
  const c = required.split(":")
  for (let i = 0; i < g.length; i++) {
    if (g[i] === "*") return i === g.length - 1
    if (i >= c.length || g[i] !== c[i]) return false
  }
  return g.length === c.length
}

export const hasPermission = (
  grants: readonly string[] | undefined,
  required: string
): boolean => !!grants && grants.some((grant) => permMatches(grant, required))
