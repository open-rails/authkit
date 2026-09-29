package verify

import "net/http"

// WithDPoPRequestURL replaces the function that returns a request's trusted,
// externally visible URL for DPoP proof checks, keeping the replay store. Use
// it on a verifier from authkit.Client.NewVerifier when a proxy rewrites paths
// or the host serves under another origin than its issuer.
func WithDPoPRequestURL(requestURL func(*http.Request) string) VerifierOption {
	return func(v *Verifier) { v.dpopRequestURL = requestURL }
}
