package authflow

import "context"

type dpopKeyCtx struct{}

// WithDPoPKey records the RFC 7638 thumbprint of the DPoP key whose proof
// accompanied a sign-in or refresh request (RFC 9449 §5), for the session it
// issues or rotates. The HTTP layer sets it after verifying the proof.
func WithDPoPKey(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, dpopKeyCtx{}, jkt)
}

// DPoPKey is the thumbprint WithDPoPKey recorded; "" when the request
// proved no key.
func DPoPKey(ctx context.Context) string {
	jkt, _ := ctx.Value(dpopKeyCtx{}).(string)
	return jkt
}
