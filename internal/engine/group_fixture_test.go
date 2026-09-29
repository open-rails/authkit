package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// seedGroup creates a group as the system, owned by the user ownerID ("" =
// no owner), and returns its id.
func seedGroup(ctx context.Context, e *Engine, persona iam.Persona, slug, ownerID string) (string, error) {
	ng := iam.NewGroup{Persona: persona, Slug: slug}
	if ownerID != "" {
		owner := iam.UserSubject(ownerID)
		ng.Owner = &owner
	}
	g, _, err := e.CreateGroup(ctx, ng)
	return g.ID, err
}

// groupIDOf resolves ref to its group id.
func groupIDOf(ctx context.Context, e *Engine, ref iam.GroupRef) (string, error) {
	g, err := e.Group(ctx, ref)
	return g.ID, err
}

// actorOf is the actor a subject acts as.
func actorOf(s iam.Subject) iam.Actor {
	if s.Kind == iam.SubjectKindRemoteApplication {
		return iam.RemoteApplicationActor(s.ID)
	}
	return iam.UserActor(s.ID)
}

// effectivePermissions is the actor's effective grants in one group.
func effectivePermissions(ctx context.Context, e *Engine, a iam.Actor, ref iam.GroupRef) ([]iam.Perm, error) {
	byGroup, err := e.EffectivePermissions(ctx, a, []iam.GroupRef{ref})
	if err != nil {
		return nil, err
	}
	for _, perms := range byGroup {
		return perms, nil
	}
	return []iam.Perm{}, nil
}
