package iam

import "strings"

// GroupRef addresses one permission group: by id, or the root group. Build it
// with GroupByID or RootGroup; the zero GroupRef addresses nothing.
type GroupRef struct {
	id   string
	root bool
}

// GroupByID addresses a group by its uuid.
func GroupByID(id string) GroupRef { return GroupRef{id: strings.TrimSpace(id)} }

// RootGroup addresses the deployment's root group.
func RootGroup() GroupRef { return GroupRef{root: true} }

// ID is the group id of a by-id reference; "" for RootGroup().
func (g GroupRef) ID() string { return g.id }

func (g GroupRef) IsZero() bool { return g == GroupRef{} }

// IsRoot reports whether g is RootGroup(). A by-id reference is never root
// until resolved.
func (g GroupRef) IsRoot() bool { return g.root }

func (g GroupRef) String() string {
	if g.root {
		return RootPersona.String()
	}
	return "id:" + g.id
}
