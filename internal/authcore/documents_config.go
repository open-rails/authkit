package authcore

import (
	"fmt"
	"strings"
)

// normalizeDocumentsConfig trims, lowercases domains, dedupes, and refuses a
// reader that does not name exactly one identity (#296).
func normalizeDocumentsConfig(c DocumentsConfig) (DocumentsConfig, error) {
	out := DocumentsConfig{AllowRegisteredTier: c.AllowRegisteredTier}
	seen := map[DocumentReader]bool{}
	for i, r := range c.Readers {
		r = DocumentReader{
			ID:     strings.TrimSpace(r.ID),
			Domain: strings.ToLower(strings.TrimSpace(r.Domain)),
			Issuer: strings.TrimSpace(r.Issuer),
		}
		set := 0
		for _, v := range []string{r.ID, r.Domain, r.Issuer} {
			if v != "" {
				set++
			}
		}
		if set != 1 {
			return DocumentsConfig{}, fmt.Errorf("authkit: Documents.Readers[%d] must set exactly one of ID, Domain, Issuer", i)
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		out.Readers = append(out.Readers, r)
	}
	return out, nil
}
