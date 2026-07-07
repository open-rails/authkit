package embedded

import (
	"context"

	authcore "github.com/open-rails/authkit/internal/authcore"
)

// GenesisClient is the explicitly-dangerous bootstrap/migration seam (#241): its
// mutators run with NO actor check and NO no-escalation enforcement — the
// opposite of the actor-checked `*As` methods on the main Client facade
// (AssignRoleBySlugAs / AssignGroupRoleAs / RemoveGroupSubjectAs). One mistaken
// call here can hand out root:*.
//
// Genesis skips ACTOR checks only. The MFA-required-role enrollment gate
// (#148/root-owner-MFA) is a subject-state invariant — "no user holds an
// MFA-required role without enrolled 2FA" — and still applies here: assigning
// such a role to a non-enrolled user fails closed with
// ErrTwoFAEnrollmentRequired. Enroll the user first, or run with
// TwoFactor.Mode: Disabled (the gate is inert then). The bootstrap manifest is
// the one seam that bypasses it (a manifest-seeded user has no session to have
// enrolled with).
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

// AssignRoleBySlug grants userID the named root-persona role with NO actor check
// and NO no-escalation enforcement. The MFA-required-role enrollment gate still
// applies (see GenesisClient). Bootstrap/migration only. Runtime callers use
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
// check and NO no-escalation enforcement. The MFA-required-role enrollment gate
// still applies (see GenesisClient). Bootstrap/migration only. Runtime callers
// use AssignGroupRoleAs.
func (g GenesisClient) AssignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return g.impl.AssignGroupRole(ctx, persona, instanceSlug, subjectID, subjectKind, role)
}

// RemoveGroupSubject revokes every role a subject holds in a group with NO actor
// check. Bootstrap/migration only — see GenesisClient. Runtime callers use
// RemoveGroupSubjectAs.
func (g GenesisClient) RemoveGroupSubject(ctx context.Context, persona, instanceSlug, subjectID, subjectKind string) error {
	return g.impl.RemoveGroupSubject(ctx, persona, instanceSlug, subjectID, subjectKind)
}
