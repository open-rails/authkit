package engine

import "slices"

// Selection controls only token inclusion. It cannot manufacture a grant and
// does not change the provider's directory/admin results or their freshness.
func selectedTokenEntitlements(allowlist, grants []string) []string {
	if len(allowlist) == 0 || len(grants) == 0 {
		return nil
	}
	active := make(map[string]bool, len(allowlist))
	for _, grant := range grants {
		if _, ok := slices.BinarySearch(allowlist, grant); ok {
			active[grant] = true
		}
	}
	var selected []string
	for _, name := range allowlist {
		if active[name] {
			selected = append(selected, name)
		}
	}
	return selected
}
