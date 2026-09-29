package httpapi

// #263: the generated persona-instance CREATION route — POST /<persona> for
// personas whose GroupCreation opts in. An authenticated user creates a group
// and is seeded as its owner; the slug rules, reserved slugs, the host
// admission seam and create-or-return-if-member idempotency live in the
// engine's CreateGroup. AuthKit owns the anti-squat velocity limits here.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

type groupInstanceCreateRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
}

func (s *Service) groupInstanceCreate(w http.ResponseWriter, r *http.Request, persona iam.Persona) {
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var body groupInstanceCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Slug) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Anti-squat velocity: a create IS a claim — capped per IP and per actor
	// (authkit owns velocity; cost gates are the host's, via the admission seam).
	if s.rateLimited(w, r, RLGroupCreate) {
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLGroupCreate, actor.String()) {
		return
	}
	g, created, err := s.svc.CreateGroup(r.Context(), actor, iam.NewGroup{Persona: persona, Slug: body.Slug, DisplayName: body.DisplayName})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	// group_id (#269) on both outcomes: the idempotent member re-run reports
	// the existing group's id.
	writeJSON(w, status, map[string]any{
		"ok":            true,
		"group_id":      g.ID,
		"persona":       persona,
		"instance_slug": g.Slug,
		"created":       created,
	})
}
