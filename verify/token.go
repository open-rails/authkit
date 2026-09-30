package verify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/enrollment"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
)

// Sender-proof errors: RFC 8705 certificate-bound and RFC 9449 DPoP-bound
// delegated tokens.
var (
	// ErrSenderProofRequired refuses a bound token presented without its
	// proof: no TLS peer or another leaf, no or an invalid DPoP proof, or a
	// token verified detached from its request.
	ErrSenderProofRequired = errmodel.E(errmodel.CodeSenderProofRequired)
	errDPoPProofRequired   = fmt.Errorf("DPoP: %w", ErrSenderProofRequired)
	// ErrSenderProofUnavailable is a DPoP replay store failure: the request
	// is refused, not proven invalid.
	ErrSenderProofUnavailable = errors.New("sender proof replay protection unavailable")
	// ErrInvalidConfirmation refuses a cnf claim that is not exactly one
	// x5t#S256 or jkt thumbprint.
	ErrInvalidConfirmation = errmodel.E(errmodel.CodeInvalidConfirmation)
	// ErrConfirmationWrongTokenType refuses cnf on a token type AuthKit does
	// not bind: an unenforced binding would be a silent downgrade.
	ErrConfirmationWrongTokenType = errmodel.E(errmodel.CodeConfirmationWrongTokenType)
)

// Verify verifies an access token or a delegated access token detached from
// any request, so a sender-bound delegated token fails with
// ErrSenderProofRequired (use VerifyRequest). ctx bounds the key fetches.
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

// VerifyDelegatedAccess is Verify accepting only a delegated access token.
func (v *Verifier) VerifyDelegatedAccess(ctx context.Context, token string) (Claims, error) {
	return delegatedOnly(v.Verify(ctx, token))
}

// VerifyDelegatedAccessRequest is VerifyRequest accepting only a delegated
// access token.
func (v *Verifier) VerifyDelegatedAccessRequest(r *http.Request) (Claims, error) {
	return delegatedOnly(v.VerifyRequest(r))
}

func delegatedOnly(cl Claims, err error) (Claims, error) {
	if err != nil {
		return Claims{}, err
	}
	if cl.Kind != iam.ActorDelegated {
		return Claims{}, errmodel.E(errmodel.CodeNotDelegatedAccessToken)
	}
	return cl, nil
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
	if cl.Kind == iam.ActorUser {
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
// profiles: an access token names a user (sub), a delegated access token an
// external actor (delegated_sub), never both.
func profile(typ string, mc map[string]any) (Claims, error) {
	sub, delegated := jose.String(mc, "sub"), jose.String(mc, "delegated_sub")
	isAccess := strings.EqualFold(typ, jose.AccessTokenType)
	isDelegated := strings.EqualFold(typ, jose.DelegatedAccessTokenType)
	switch {
	case sub != "" && delegated != "":
		return Claims{}, errmodel.E(errmodel.CodeConflictingSubject)
	case isDelegated && sub != "":
		return Claims{}, errmodel.E(errmodel.CodeAccessTokenHasSub)
	case delegated != "" && !isDelegated:
		return Claims{}, errmodel.E(errmodel.CodeDelegatedAccessWrongTyp)
	case sub != "" && !isAccess:
		return Claims{}, errmodel.E(errmodel.CodeAccessTokenWrongTyp)
	case typ == "":
		return Claims{}, errmodel.E(errmodel.CodeMissingTokenTyp)
	case !isAccess && !isDelegated:
		return Claims{}, errmodel.E(errmodel.CodeUnsupportedTokenTyp)
	case isDelegated && delegated == "":
		return Claims{}, errmodel.E(errmodel.CodeMissingDelegatedSub)
	case isAccess && sub == "":
		return Claims{}, errmodel.E(errmodel.CodeMissingSub)
	case isDelegated && jose.String(mc, "user_tier") != "":
		return Claims{}, errmodel.E(errmodel.CodeDelegatedAccessHasUserTier)
	case isDelegated && len(jose.Strings(mc, "roles")) > 0:
		return Claims{}, errmodel.E(errmodel.CodeDelegatedAccessHasRoles)
	}
	cl := Claims{
		Kind:             iam.ActorUser,
		JOSEType:         typ,
		Issuer:           jose.String(mc, "iss"),
		Subject:          sub,
		DelegatedSubject: delegated,
		SessionID:        jose.String(mc, "sid"),
		DeviceKeyID:      jose.String(mc, "device_key_id"),
		Permissions:      jose.Strings(mc, "permissions"),
		Attributes:       jose.Object(mc, "attributes"),
		Entitlements:     jose.Strings(mc, "entitlements"),
		RootRole:         jose.String(mc, "root_role"),
		Email:            jose.String(mc, "email"),
		Username:         jose.String(mc, "username"),
		AMR:              jose.Strings(mc, "amr"),
		ACR:              jose.String(mc, "acr"),
		JTI:              jose.String(mc, "jti"),
	}
	cl.EmailVerified, _ = mc["email_verified"].(bool)
	cl.TwoFAEnrollment, _ = mc["2fa_enrollment"].(bool)
	cl.MFAEnrolled, _ = mc["mfa_enrolled"].(bool)
	cl.AuthTime, _ = jose.Time(mc, "auth_time")
	if isDelegated {
		cl.Kind, cl.RootRole = iam.ActorDelegated, ""
	}
	return cl, nil
}

// senderProof enforces a delegated token's cnf binding against r: the TLS
// peer certificate for x5t#S256, a fresh DPoP proof for jkt. A DPoP request
// must carry a DPoP-bound token.
func (v *Verifier) senderProof(token string, r *http.Request, cl *Claims) error {
	member, thumbprint, err := jose.Confirmation(token)
	if err != nil {
		return ErrInvalidConfirmation
	}
	if member != "" && cl.Kind != iam.ActorDelegated {
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
		if !isDPoPRequest(r) || v.origin == "" || v.dpopReplay == nil {
			return errDPoPProofRequired
		}
		if _, err := dpop.VerifyRequest(r, v.origin+r.URL.EscapedPath(), token, thumbprint, v.dpopReplay); err != nil {
			if errors.Is(err, dpop.ErrReplayUnavailable) {
				return errmodel.Internal("sender_proof_replay", fmt.Errorf("%w: %w", ErrSenderProofUnavailable, err))
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

func isDPoPRequest(r *http.Request) bool {
	_, dpop := jose.RequestToken(r)
	return dpop
}
