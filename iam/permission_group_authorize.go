package iam

// AnyGrantCovers reports whether any grant pattern covers the concrete perm,
// under the namespace-anchored matching of Perm.Matches.
func AnyGrantCovers(grants []string, perm Perm) bool {
	for _, g := range grants {
		if perm.Matches(Perm(g)) {
			return true
		}
	}
	return false
}
