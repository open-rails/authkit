package authhttp

// #262: the user-metadata HTTP surface. GET|PATCH /user/metadata expose the
// authenticated user's own metadata map — the store hosts already reach through
// Client.GetUserMetadata/PatchUserMetadata, without the wrapper route every
// host used to write. Keys are HOST-namespaced by convention (e.g.
// "cozy_avatar"); the keys authkit itself owns (internal/admin flags such as
// "reserved") are invisible here: filtered from reads, rejected on writes.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/verify"
)

// internalMetadataKeys are authkit-owned metadata flags the HTTP surface never
// exposes: hidden from GET, rejected on PATCH. (The Go-API Client methods are
// host-trusted and stay unfiltered.)
var internalMetadataKeys = map[string]struct{}{
	"reserved": {}, // reserved-account placeholder flag (login gate reads it)
}

const maxMetadataKeyLen = 128

func metadataKeyAllowed(key string) bool {
	if key == "" || len(key) > maxMetadataKeyLen {
		return false
	}
	if _, internal := internalMetadataKeys[key]; internal {
		return false
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e { // printable ASCII, no spaces/control chars
			return false
		}
	}
	return true
}

func hostVisibleMetadata(meta map[string]any) map[string]any {
	out := make(map[string]any, len(meta))
	for k, v := range meta {
		if _, internal := internalMetadataKeys[k]; internal {
			continue
		}
		out[k] = v
	}
	return out
}

func (s *Service) handleUserMetadataGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserMetadata) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	meta, err := s.svc.GetUserMetadata(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrUserLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"metadata": hostVisibleMetadata(meta)})
}

func (s *Service) handleUserMetadataPATCH(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserMetadata) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var patch map[string]any
	if err := decodeJSON(r, &patch); err != nil || len(patch) == 0 {
		badRequest(w, ErrInvalidRequest)
		return
	}
	for key := range patch {
		if _, internal := internalMetadataKeys[strings.TrimSpace(key)]; internal {
			badRequest(w, ErrMetadataKeyReserved)
			return
		}
		if !metadataKeyAllowed(key) {
			badRequest(w, ErrInvalidRequest)
			return
		}
	}
	if err := s.svc.PatchUserMetadata(r.Context(), claims.UserID, patch); err != nil {
		serverErr(w, ErrDatabaseError)
		return
	}
	meta, err := s.svc.GetUserMetadata(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrUserLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "metadata": hostVisibleMetadata(meta)})
}
