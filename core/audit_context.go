package core

import "context"

type authCtxKey string

const authCtxKeySessionRevokeReason authCtxKey = "authkit.session_revoke_reason"

// WithSessionRevokeReason annotates ctx so revoke paths can emit a structured reason to the auth logger.
func WithSessionRevokeReason(ctx context.Context, reason SessionRevokeReason) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if reason == "" {
		return context.WithValue(ctx, authCtxKeySessionRevokeReason, nil)
	}
	return context.WithValue(ctx, authCtxKeySessionRevokeReason, string(reason))
}

func sessionRevokeReasonFromContext(ctx context.Context) *string {
	if ctx == nil {
		return nil
	}
	v := ctx.Value(authCtxKeySessionRevokeReason)
	if v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}
