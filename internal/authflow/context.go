package authflow

import (
	"context"
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
