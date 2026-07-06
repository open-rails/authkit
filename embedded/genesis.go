package embedded

import (
	"context"

	authcore "github.com/open-rails/authkit/internal/authcore"
)

// GenesisClient is the explicitly-dangerous bootstrap/migration seam (#241): its
// mutators run with NO actor check, NO no-escalation enforcement, and NO
// MFA-required-role gate — the opposite of the actor-checked `*As` methods on
// the main Client facade
// (AssignRoleBySlugAs / AssignGroupRoleAs / RemoveGroupSubjectAs). One mistaken
// call here can hand out root:*.
//
// Reach it via Client.Genesis(). Use it ONLY for one-time bootstrap/seed/
// migration code that runs before any actor-authorized request path exists
// (e.g. provisioning the first owner of a fresh install) — never from a runtime
// request handler, where the corresponding `*As` method belongs.
type GenesisClient struct {
	impl *authcore.Service
}

// Genesis returns the unchecked bootstrap/migration sub-client. See GenesisClient.
func (s *Client) Genesis() GenesisClient {
	return GenesisClient{impl: s.impl}
}

// AssignRoleBySlug grants userID the named root-persona role with NO actor
// check, NO no-escalation enforcement, and NO MFA-required-role gate.
// Bootstrap/migration only — see GenesisClient. Runtime callers use
// AssignRoleBySlugAs.
func (g GenesisClient) AssignRoleBySlug(ctx context.Context, userID, slug string) error {
	return g.impl.AssignRoleBySlug(ctx, userID, slug)
}

// RemoveRoleBySlug revokes userID's named root-persona role with NO actor check
// and NO no-escalation enforcement. Bootstrap/migration only — see GenesisClient.
// Runtime callers use RemoveRoleBySlugAs.
func (g GenesisClient) RemoveRoleBySlug(ctx context.Context, userID, slug string) error {
	return g.impl.RemoveRoleBySlug(ctx, userID, slug)
}

// AssignGroupRole grants a role to a subject in a permission group with NO actor
// check, NO no-escalation enforcement, and NO MFA-required-role gate.
// Bootstrap/migration only — see GenesisClient. Runtime callers use
// AssignGroupRoleAs.
func (g GenesisClient) AssignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return g.impl.AssignGroupRoleGenesis(ctx, persona, instanceSlug, subjectID, subjectKind, role)
}

// RemoveGroupSubject revokes every role a subject holds in a group with NO actor
// check. Bootstrap/migration only — see GenesisClient. Runtime callers use
// RemoveGroupSubjectAs.
func (g GenesisClient) RemoveGroupSubject(ctx context.Context, persona, instanceSlug, subjectID, subjectKind string) error {
	return g.impl.RemoveGroupSubject(ctx, persona, instanceSlug, subjectID, subjectKind)
}
