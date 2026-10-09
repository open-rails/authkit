package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/enrollment"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
)

// Sender-proof errors: RFC 8705 certificate-bound and RFC 9449 DPoP-bound
// resource tokens.
var (
	// ErrSenderProofRequired refuses a bound token presented without its
	// proof: no TLS peer or another leaf, no or an invalid DPoP proof, or a
	// token verified detached from its request.
	ErrSenderProofRequired iam.Error = errmodel.E(errmodel.CodeSenderProofRequired)
	errDPoPProofRequired             = fmt.Errorf("DPoP: %w", ErrSenderProofRequired)
	// ErrSenderProofUnavailable is a DPoP replay store failure: the request
	// is refused, not proven invalid.
	ErrSenderProofUnavailable = errors.New("sender proof replay protection unavailable")
	// ErrInvalidConfirmation refuses a cnf claim that is not exactly one
	// x5t#S256 or jkt thumbprint.
	ErrInvalidConfirmation iam.Error = errmodel.E(errmodel.CodeInvalidConfirmation)
	// ErrConfirmationWrongTokenType refuses cnf on a token type AuthKit does
	// not bind: an unenforced binding would be a silent downgrade.
	ErrConfirmationWrongTokenType iam.Error = errmodel.E(errmodel.CodeConfirmationWrongTokenType)
)

// Verify verifies a token detached from any request, so a sender-bound
// token fails with ErrSenderProofRequired (use VerifyRequest). ctx bounds
// the key fetches.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	return v.verify(ctx, token, nil)
}

// VerifyRequest verifies the request's bearer (or DPoP) token, its sender
// proof included. It is stateless: a token outlives its revoked session until
// it expires; RequireSession, RequirePermission and Sensitive check the
// session live (through *authkit.Client).
func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error) {
	token, _ := jose.RequestToken(r)
	if token == "" {
		return Claims{}, errmodel.E(errmodel.CodeUnauthenticated)
	}
	return v.verify(r.Context(), token, r)
}

// verify runs one token through the AuthKit token profiles; r, when set, is
// the request that carries it and its sender proof.
func (v *Verifier) verify(ctx context.Context, token string, r *http.Request) (Claims, error) {
	typ, mc, is, err := v.parse(ctx, token)
	if err != nil {
		return Claims{}, err
	}
	cl, err := profile(typ, mc)
	if err != nil {
		return Claims{}, err
	}
	if cl.IsResourceToken() && !is.local {
		// Only this deployment's device keys mean anything here (#437).
		cl.DeviceKeyID = ""
	}
	if cl.Kind == TokenUser && !cl.IsResourceToken() {
		if is.local {
			// Native tokens establish identity, never authority.
			cl.UserID, cl.Permissions = cl.Subject, nil
			cl.Subject = ""
		} else {
			cl.RootRole = "" // AuthKit's display hint, not another issuer's
		}
		if cl.TwoFAEnrollment && !enrollment.IsRoute(ctx) {
			return Claims{}, errmodel.E(errmodel.CodeForbidden)
		}
	}
	if err := v.senderProof(token, r, &cl); err != nil {
		return Claims{}, err
	}
	return cl, nil
}

// profile maps a signature-verified token to Claims under AuthKit's
// profiles: an access token names a user (sub); a resource access token
// (RFC 9068 at+jwt) names a user, or its client acting for itself, with the
// client_id it was issued to.
func profile(typ string, mc map[string]any) (Claims, error) {
	sub := jose.String(mc, "sub")
	isAccess := strings.EqualFold(typ, jose.AccessTokenType)
	isResource := isResourceType(typ)
	clientID := jose.String(mc, "client_id")
	switch {
	case typ == "":
		return Claims{}, errmodel.E(errmodel.CodeMissingTokenTyp)
	case !isAccess && !isResource:
		return Claims{}, errmodel.E(errmodel.CodeUnsupportedTokenTyp)
	case sub == "":
		return Claims{}, errmodel.E(errmodel.CodeMissingSub)
	case isResource && clientID == "":
		return Claims{}, errmodel.E(errmodel.CodeMissingClientID)
	}
	cl := Claims{
		Kind:         TokenUser,
		JOSEType:     typ,
		Issuer:       jose.String(mc, "iss"),
		Subject:      sub,
		SessionID:    jose.String(mc, "sid"),
		DeviceKeyID:  jose.String(mc, "device_key_id"),
		Permissions:  jose.Strings(mc, "permissions"),
		Entitlements: jose.Strings(mc, "entitlements"),
		RootRole:     jose.String(mc, "root_role"),
		Email:        jose.String(mc, "email"),
		Username:     jose.String(mc, "username"),
		AMR:          jose.Strings(mc, "amr"),
		ACR:          jose.String(mc, "acr"),
		JTI:          jose.String(mc, "jti"),
	}
	cl.EmailVerified, _ = mc["email_verified"].(bool)
	cl.TwoFAEnrollment, _ = mc["2fa_enrollment"].(bool)
	cl.MFAEnrolled, _ = mc["mfa_enrolled"].(bool)
	cl.AuthTime, _ = jose.Time(mc, "auth_time")
	if isResource {
		cl.ClientID, cl.Scopes, cl.Roles = clientID, strings.Fields(jose.String(mc, "scope")), jose.Strings(mc, "roles")
		cl.RootRole, cl.TwoFAEnrollment, cl.MFAEnrolled = "", false, false
		if sub == clientID {
			cl.Kind = TokenOAuthClient
		}
		if act, ok := mc["act"].(map[string]any); ok {
			cl.Invoker, _ = act["sub"].(string)
		}
		if details, ok := mc["authorization_details"].([]any); ok {
			cl.AuthorizationDetails, _ = json.Marshal(details)
		}
		cl.CustomClaims = uriClaims(mc)
	}
	return cl, nil
}

// uriClaims is mc's claims named by an absolute URI, each as raw JSON; nil
// when there are none.
func uriClaims(mc map[string]any) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	for name, value := range mc {
		if u, err := url.Parse(name); err != nil || !u.IsAbs() || u.Host == "" {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			continue
		}
		if out == nil {
			out = map[string]json.RawMessage{}
		}
		out[name] = raw
	}
	return out
}

// isResourceType is RFC 9068's typ, bare or as its media type.
func isResourceType(typ string) bool {
	return strings.EqualFold(typ, jose.ResourceAccessTokenType) || strings.EqualFold(typ, "application/"+jose.ResourceAccessTokenType)
}

// senderProof enforces a resource token's cnf binding against
// r: the TLS peer certificate for x5t#S256, a fresh DPoP proof for jkt. A
// DPoP request must carry a DPoP-bound token.
func (v *Verifier) senderProof(token string, r *http.Request, cl *Claims) error {
	member, thumbprint, err := jose.Confirmation(token)
	if err != nil {
		return ErrInvalidConfirmation
	}
	if member != "" && !cl.IsResourceToken() {
		return ErrConfirmationWrongTokenType
	}
	if isDPoPRequest(r) && member != jose.JWKThumbprintMember {
		return errDPoPProofRequired
	}
	switch member {
	case jose.CertificateThumbprintMember:
		if peer := peerCertificateThumbprint(r); peer == "" || peer != thumbprint {
			return ErrSenderProofRequired
		}
		cl.CertificateThumbprint = thumbprint
	case jose.JWKThumbprintMember:
		if !isDPoPRequest(r) || v.publicURL == "" || v.dpopReplay == nil {
			return errDPoPProofRequired
		}
		if _, err := dpop.Verify(r, dpop.Check{URL: v.publicURL + r.URL.EscapedPath(), AccessToken: token, Thumbprint: thumbprint, Replay: v.dpopReplay, Nonces: v.dpopNonces}); err != nil {
			switch {
			case errors.Is(err, dpop.ErrReplayUnavailable):
				return errmodel.Internal("sender_proof_replay", fmt.Errorf("%w: %w", ErrSenderProofUnavailable, err))
			case errors.Is(err, dpop.ErrNonceRequired):
				return errmodel.E(errmodel.CodeUseDPoPNonce, errmodel.WithCause(dpopNonce(v.dpopNonces.Issue(time.Now()))))
			}
			return errDPoPProofRequired
		}
		cl.JWKThumbprint = thumbprint
	}
	return nil
}

// peerCertificateThumbprint is the x5t#S256 of the TLS-authenticated peer
// leaf; "" when the request has none. No header can stand in for it.
func peerCertificateThumbprint(r *http.Request) string {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return ""
	}
	return jose.CertificateThumbprint(r.TLS.PeerCertificates[0].Raw)
}

// dpopNonce is the fresh server nonce a use_dpop_nonce refusal carries.
type dpopNonce string

func (n dpopNonce) Error() string { return "DPoP nonce required" }

// DPoPChallenge sets the RFC 9449 response headers for err, a failed
// authentication of r: WWW-Authenticate naming the DPoP error, and the
// DPoP-Nonce to retry with. It sets nothing for an error unrelated to DPoP.
// The gates call it; a host writing its own refusals calls it first.
func DPoPChallenge(w http.ResponseWriter, r *http.Request, err error) {
	var nonce dpopNonce
	switch {
	case errors.As(err, &nonce):
		w.Header().Set("DPoP-Nonce", string(nonce))
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof", algs="ES256"`)
	case errors.Is(err, errDPoPProofRequired) || (isDPoPRequest(r) && errors.Is(err, ErrSenderProofRequired)):
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
	case isDPoPRequest(r):
		if e := errmodel.As(err); e == nil || e.Status() == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", algs="ES256"`)
		}
	}
}

func isDPoPRequest(r *http.Request) bool {
	_, dpop := jose.RequestToken(r)
	return dpop
}
