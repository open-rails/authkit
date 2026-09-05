package authhttp

// #263: the generated persona-instance CREATION route — POST /<persona> for
// personas whose InstanceCreationDef opts in. An authenticated USER creates a
// group instance and is seeded as its owner; slug pattern, reserved-slug
// escalation, the host admission seam, and create-or-return-if-member
// idempotency live in the core create path (CreateInstanceForSubject). AuthKit
// owns the anti-squat velocity limits here (per-IP + per-user); host cost
// gates plug in via WithInstanceAdmission.

import (
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
)

type groupInstanceCreateRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
}

func (s *Service) groupInstanceCreate(w http.ResponseWriter, r *http.Request, persona authkit.Persona) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		// Instance ownership needs a user subject; machine principals cannot
		// create through this route.
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}
	var body groupInstanceCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Slug) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	// Anti-squat velocity: a create IS a claim — capped per IP and per user
	// (authkit owns velocity; cost gates are the host's, via the admission seam).
	if s.rateLimited(w, r, RLGroupCreate) {
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLGroupCreate, claims.UserID) {
		return
	}
	res, err := s.svc.CreateInstanceForSubject(r.Context(), authkit.GroupRef{Persona: persona, Instance: body.Slug}, body.DisplayName, claims.UserID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	// group_id (#269): the instance's uuid, on BOTH outcomes. A host that owns
	// the money for an instance has to be able to address it in its own ledger,
	// and creation is where it learns the instance exists; the idempotent
	// member re-run reports the same id rather than nothing.
	writeJSON(w, status, map[string]any{
		"ok":            true,
		"group_id":      res.GroupID,
		"persona":       persona,
		"instance_slug": res.InstanceSlug,
		"created":       res.Created,
	})
}
