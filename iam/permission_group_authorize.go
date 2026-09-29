package iam

// AnyGrantCovers reports whether any grant pattern covers the concrete perm,
// under the namespace-anchored matching of Perm.Matches.
func AnyGrantCovers(grants []Perm, perm Perm) bool {
	for _, g := range grants {
		if perm.Matches(g) {
			return true
		}
	}
	return false
}
