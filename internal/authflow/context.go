package authflow

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/iam"
)

type sessionRevokeReasonKey struct{}

// WithSessionRevokeReason annotates ctx so revoke paths can record a
// structured reason in the session log.
func WithSessionRevokeReason(ctx context.Context, reason SessionRevokeReason) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sessionRevokeReasonKey{}, string(reason))
}

// SessionRevokeReasonFrom reads the reason WithSessionRevokeReason attached,
// or nil.
func SessionRevokeReasonFrom(ctx context.Context) *string {
	if ctx == nil {
		return nil
	}
	s, ok := ctx.Value(sessionRevokeReasonKey{}).(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}

type resolvedGroupKey struct{}

// ResolvedGroup is a group address an HTTP request already resolved to its
// immutable target.
type ResolvedGroup struct {
	Persona       iam.Persona
	Reference, ID string
}

// WithResolvedGroup binds the address already resolved by an HTTP request to its
// immutable target. It confers no permission: the caller must still authorize.
// Only this exact persona/reference matches. Parent and other-target lookups keep
// normal resolution. Every use rechecks target liveness and never falls back to
// the name if the captured group has been deleted.
func WithResolvedGroup(ctx context.Context, g iam.Group, reference string) context.Context {
	return context.WithValue(ctx, resolvedGroupKey{}, ResolvedGroup{Persona: g.Persona, Reference: strings.ToLower(strings.TrimSpace(reference)), ID: g.ID})
}

// ResolvedGroupFrom reads the group WithResolvedGroup bound, if any.
func ResolvedGroupFrom(ctx context.Context) (ResolvedGroup, bool) {
	g, ok := ctx.Value(resolvedGroupKey{}).(ResolvedGroup)
	return g, ok
}
