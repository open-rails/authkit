package embedded

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxTokenEntitlements         = 32
	maxTokenEntitlementNameBytes = 128
	maxTokenEntitlementBytes     = 2048
)

func normalizeEntitlementAllowlist(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	unique := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" || strings.TrimSpace(name) != name || !utf8.ValidString(name) || len(name) > maxTokenEntitlementNameBytes {
			return nil, fmt.Errorf("authkit: Token.EntitlementAllowlist names must be nonempty UTF-8 values without surrounding whitespace and at most %d bytes", maxTokenEntitlementNameBytes)
		}
		unique[name] = struct{}{}
		if len(unique) > maxTokenEntitlements {
			return nil, fmt.Errorf("authkit: Token.EntitlementAllowlist exceeds %d distinct names", maxTokenEntitlements)
		}
	}
	out := make([]string, 0, len(unique))
	for name := range unique {
		out = append(out, name)
	}
	slices.Sort(out)
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > maxTokenEntitlementBytes {
		return nil, fmt.Errorf("authkit: Token.EntitlementAllowlist exceeds %d encoded bytes", maxTokenEntitlementBytes)
	}
	return out, nil
}

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
