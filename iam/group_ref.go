package iam

import "strings"

// GroupRef addresses one permission group: by id, by persona and slug, or the
// root group. Build it with GroupByID, GroupBySlug or RootGroup; the zero
// GroupRef addresses nothing.
type GroupRef struct {
	id      string
	persona Persona
	slug    string
}

// GroupByID addresses a group by its uuid.
func GroupByID(id string) GroupRef { return GroupRef{id: strings.TrimSpace(id)} }

// GroupBySlug addresses a live group by persona and slug. The slug is
// lower-cased; for the root persona it is ignored.
func GroupBySlug(p Persona, slug string) GroupRef {
	p = Persona(strings.TrimSpace(string(p)))
	if p == RootPersona {
		return RootGroup()
	}
	return GroupRef{persona: p, slug: strings.ToLower(strings.TrimSpace(slug))}
}

// RootGroup addresses the deployment's root group.
func RootGroup() GroupRef { return GroupRef{persona: RootPersona} }

// ID is the group id of a by-id reference; "" otherwise.
func (g GroupRef) ID() string { return g.id }

// Persona is the persona of a by-slug or root reference; "" for a by-id one.
func (g GroupRef) Persona() Persona { return g.persona }

// Slug is the slug of a by-slug reference; "" otherwise.
func (g GroupRef) Slug() string { return g.slug }

func (g GroupRef) IsZero() bool { return g == GroupRef{} }

// IsRoot reports whether g is RootGroup(). A by-id reference is never root
// until resolved.
func (g GroupRef) IsRoot() bool { return g.id == "" && g.persona == RootPersona }

func (g GroupRef) String() string {
	switch {
	case g.id != "":
		return "id:" + g.id
	case g.slug == "":
		return string(g.persona)
	}
	return string(g.persona) + "/" + g.slug
}
