package authhttp

import (
	"os"
	"regexp"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
)

// #213 parity guard — the real invariant between the two code tables.
//
// The audit's premise ("two parallel registries with the same strings") turned
// out only PARTIALLY true: the authkit sentinel registry is the MANAGEMENT
// transport's wire vocabulary (server/ emits sentinel codes verbatim via
// HTTPStatus), while authhttp's ~200 ErrorCode consts are the HTTP route
// vocabulary — overlapping, but with DELIBERATE divergences (e.g. the
// cannot_remove_last_admin_role sentinel surfaces as cannot_remove_last_owner
// on the group routes, and the siws_* sentinels surface as challenge_expired /
// invalid_signature). Forcing 1:1 parity would mean ~30 dead consts.
//
// What must hold instead: every registry code is ACCOUNTED FOR — either it has
// an identical authhttp const, or it is explicitly listed as management-only /
// exempt below. A new sentinel that is none of these fails loudly, so the two
// tables can never drift silently. (This replaces codegen: generation would
// need the same hand-lists anyway.)
func TestSentinelCodesAccountedFor(t *testing.T) {
	src, err := os.ReadFile("error_codes.go")
	if err != nil {
		t.Fatalf("read error_codes.go: %v", err)
	}
	constRe := regexp.MustCompile(`ErrorCode = "([^"]+)"`)
	declared := map[string]bool{}
	for _, m := range constRe.FindAllStringSubmatch(string(src), -1) {
		declared[m[1]] = true
	}
	if len(declared) < 100 {
		t.Fatalf("suspiciously few ErrorCode consts parsed (%d) — regex drift?", len(declared))
	}
	// Consts whose values are indirect (ErrorCode = embedded.ErrCode…) — the
	// regex can't see them, so account for them by VALUE via the consts themselves.
	for _, c := range []ErrorCode{
		ErrInvalidEmail, ErrInvalidPhoneNumber, ErrOwnerSlugTaken, ErrPasswordTooShort,
		ErrRenameRateLimited, ErrUsernameCannotContainAt, ErrUsernameCannotStartWithPlus,
		ErrUsernameInvalidCharacters, ErrUsernameMustStartWithLetter, ErrUsernameNotAllowed,
		ErrUsernameTooLong, ErrUsernameTooShort,
	} {
		declared[string(c)] = true
	}

	// Management-transport-only codes: authhttp handlers deliberately map these
	// sentinels to OTHER wire codes on their routes (or the condition never
	// reaches an authhttp route at all). They travel verbatim only on the
	// server/ management API. Adding a same-named authhttp const would be dead.
	managementOnly := map[string]bool{
		"cannot_remove_last_admin_role":         true, // group routes emit cannot_remove_last_owner
		"account_registration_invite_consumed":  true, // registration gate surfaces registration_disabled
		"account_registration_invite_expired":   true,
		"account_registration_invite_not_found": true,
		"account_registration_invite_revoked":   true,
		"custom_jwt_reserved_claim":             true, // MintCustomJWT is Go-API/management only
		"custom_jwt_reserved_type":              true,
		"custom_jwt_empty_claims":               true,
		"custom_jwt_too_many_claims":            true,
		"external_invites_disabled":             true, // group routes emit forbidden
		"permission_group_not_found":            true, // group routes emit not_found
		"insufficient_role_authority":           true, // group routes emit forbidden
		"role_assignment_escalation":            true, // group routes emit forbidden
		"invalid_attribute_def":                 true, // remote-app attribute defs: management only
		"invalid_bootstrap_manifest":            true, // bootstrap/ops path
		"bootstrap_database_not_empty":          true, // bootstrap/ops path
		"group_invite_link_expired":             true, // group routes emit invalid_request
		"group_invite_link_not_found":           true, // group routes emit not_found
		"group_invite_link_revoked":             true, // group routes emit invalid_request
		"missing_signer":                        true, // verify-only misconfig, construction/Go-API
		"not_group_member":                      true, // no authhttp route surfaces it; management/Go-API only
		"passkey_clone_detected":                true, // passkey login surfaces invalid_credentials
		"passkey_not_found":                     true, // passkey routes emit not_found
		"passkey_user_verification_required":    true, // surfaces as invalid_credentials
		"user_role_not_found":                   true, // role routes emit not_found
		"reserved_issuer":                       true, // remote-app routes emit invalid_request
		"siws_address_mismatch":                 true, // solana routes emit address_mismatch
		"siws_challenge_expired":                true, // solana routes emit challenge_expired
		"siws_challenge_not_found":              true, // solana routes emit challenge_expired
		"siws_domain_invalid":                   true, // solana routes emit authentication_failed
		"siws_signature_invalid":                true, // solana routes emit invalid_signature
		"siws_timestamp_invalid":                true, // solana routes emit challenge_expired
		// #247: permission-group hardening — group/invite/api-key input errors are
		// sentinels now (errors.Is, replacing strings.Contains) but the group
		// routes still collapse them onto the generic invalid_request wire code.
		"role_not_assignable":               true,
		"invalid_role":                      true,
		"unknown_role":                      true,
		"missing_name":                      true,
		"invalid_invite":                    true,
		"invalid_expiry":                    true,
		"unknown_group_persona":             true,
		"custom_roles_not_supported":        true,
		"custom_role_name_invalid":          true,
		"custom_role_is_catalog_role":       true,
		"custom_role_grant_cross_persona":   true,
		"custom_role_grant_outside_catalog": true,
	}
	// Signed-document errors are surfaced by the generic management Client
	// methods and documents/verify APIs, not by authhttp route handlers.
	for _, sentinel := range []error{
		documents.ErrInvalidReference, documents.ErrInvalidType, documents.ErrInvalidDigest,
		documents.ErrDuplicateReference, documents.ErrTooManyReferences, documents.ErrReferencesTooLarge,
		documents.ErrWrongTokenType, documents.ErrReservedAttribute, documents.ErrInvalidEnvelope,
		documents.ErrPayloadTooLarge, documents.ErrMalformedJWS, documents.ErrWrongJOSEType,
		documents.ErrUnsupportedAlgorithm, documents.ErrUnsupportedSigner, documents.ErrUnknownKey,
		documents.ErrInvalidSignature, documents.ErrDigestMismatch, documents.ErrIssuerMismatch,
		documents.ErrAudienceMismatch, documents.ErrTypeMismatch, documents.ErrUntrustedIssuer,
		documents.ErrUnauthorized, documents.ErrNotFound, documents.ErrFetch, documents.ErrRedirect,
	} {
		managementOnly[sentinel.Error()] = true
	}

	for _, code := range authkit.ErrorCodes() {
		if declared[code] || managementOnly[code] {
			continue
		}
		t.Errorf("registry code %q is unaccounted for: add a matching authhttp.ErrorCode const, or classify it in managementOnly with a reason", code)
	}
}
