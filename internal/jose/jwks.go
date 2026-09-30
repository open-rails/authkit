package jose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/open-rails/authkit/keys"
)

// ServeJWKS writes ks with the caching contract a CDN-fronted JWKS needs:
// ETag and Cache-Control on every answer, the 304 included (RFC 7232 requires
// the validator there); If-None-Match matched per RFC 7232 §3.2 ("*", lists,
// weak "W/"); and nosniff.
func ServeJWKS(w http.ResponseWriter, r *http.Request, ks keys.JWKS) {
	b, _ := json.Marshal(ks)
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`

	h := w.Header()
	h.Set("Cache-Control", "public, max-age=300, must-revalidate")
	h.Set("ETag", etag)
	h.Set("X-Content-Type-Options", "nosniff")
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// etagMatches is If-None-Match's weak comparison (RFC 7232 §2.3.2).
func etagMatches(ifNoneMatch, etag string) bool {
	ifNoneMatch = strings.TrimSpace(ifNoneMatch)
	if ifNoneMatch == "*" {
		return true
	}
	etag = strings.TrimPrefix(etag, "W/")
	for candidate := range strings.SplitSeq(ifNoneMatch, ",") {
		if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == etag {
			return true
		}
	}
	return false
}

// JWKS publishes a key source's public keys, sorted by kid; the active key
// carries its signer's alg.
func JWKS(src keys.Source) keys.JWKS {
	activeKID, activeAlg := "", ""
	if active := src.ActiveSigner(); active != nil {
		activeKID, activeAlg = active.KID(), active.Algorithm()
	}
	pubs := src.PublicKeys()
	kids := make([]string, 0, len(pubs))
	for kid := range pubs {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	ks := keys.JWKS{Keys: make([]keys.JWK, 0, len(kids))}
	for _, kid := range kids {
		alg := ""
		if kid == activeKID {
			alg = activeAlg
		}
		ks.Keys = append(ks.Keys, keys.PublicJWK(pubs[kid], kid, alg))
	}
	return ks
}
