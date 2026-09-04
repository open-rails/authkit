package authhttp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
		"avatar_url_invalid":                    true, // UpdateAvatarURL is Go-API/management only (#262)
		"missing_signer":                        true, // verify-only misconfig, construction/Go-API
		"not_group_member":                      true, // no authhttp route surfaces it; management/Go-API only
		"passkey_clone_detected":                true, // passkey login surfaces invalid_credentials
		"passkey_not_found":                     true, // passkey routes emit not_found
		"passkey_user_verification_required":    true, // surfaces as invalid_credentials
		"user_role_not_found":                   true, // role routes emit not_found
		"user_referenced":                       true, // hard delete is Go-API/management only (#304)
		"reserved_issuer":                       true, // remote-app routes emit invalid_request
		"siws_address_mismatch":                 true, // solana routes emit address_mismatch
		"siws_challenge_expired":                true, // solana routes emit challenge_expired
		"siws_challenge_mismatch":               true, // solana routes emit authentication_failed
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
		documents.ErrDigestCollision,
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

// #290 stage 1 — the reverse guard. TestSentinelCodesAccountedFor proves every
// registry code has a const; it can never notice a const nobody emits (64 such
// remnants of removed surfaces were deleted in #290). This walks the module for
// non-test references to each ErrorCode const: every const must be referenced
// outside error_codes.go, mirror a registry sentinel (parity, above), or sit
// on the explicit exemption list with a reason.
func TestErrorCodeConstsAreEmitted(t *testing.T) {
	const authhttpPath = "github.com/open-rails/authkit/authhttp"
	// Emitted by VALUE: handlers write ErrorCode(embedded.ValidationErrorCode(err)),
	// so the const exists for consumers to compare against, not for handlers.
	exempt := map[string]string{
		"ErrInvalidEmail":                "value-indirect validation code",
		"ErrInvalidPhoneNumber":          "value-indirect validation code",
		"ErrOwnerSlugTaken":              "value-indirect validation code",
		"ErrPasswordTooShort":            "value-indirect validation code",
		"ErrRenameRateLimited":           "value-indirect validation code",
		"ErrUsernameCannotContainAt":     "value-indirect validation code",
		"ErrUsernameCannotStartWithPlus": "value-indirect validation code",
		"ErrUsernameInvalidCharacters":   "value-indirect validation code",
		"ErrUsernameMustStartWithLetter": "value-indirect validation code",
		"ErrUsernameNotAllowed":          "value-indirect validation code",
		"ErrUsernameTooLong":             "value-indirect validation code",
		"ErrUsernameTooShort":            "value-indirect validation code",
	}
	registry := map[string]bool{}
	for _, code := range authkit.ErrorCodes() {
		registry[code] = true
	}

	fset := token.NewFileSet()
	decl, err := parser.ParseFile(fset, "error_codes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse error_codes.go: %v", err)
	}
	values := map[string]string{} // const name -> literal wire value ("" when indirect)
	for _, d := range decl.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if ident, ok := vs.Type.(*ast.Ident); !ok || ident.Name != "ErrorCode" {
				continue
			}
			for i, name := range vs.Names {
				value := ""
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					value, _ = strconv.Unquote(lit.Value)
				}
				values[name.Name] = value
			}
		}
	}
	if len(values) < 100 {
		t.Fatalf("suspiciously few ErrorCode consts parsed (%d)", len(values))
	}

	referenced := map[string]bool{}
	err = filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != ".." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		rel := filepath.ToSlash(path)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || rel == "../authhttp/error_codes.go" {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		samePackage := f.Name.Name == "authhttp" && filepath.ToSlash(filepath.Dir(path)) == "../authhttp"
		qualifier := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == authhttpPath {
				qualifier = "authhttp"
				if imp.Name != nil {
					qualifier = imp.Name.Name
				}
			}
		}
		if !samePackage && qualifier == "" {
			return nil
		}
		mark := func(name string) {
			if _, known := values[name]; known {
				referenced[name] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := node.X.(*ast.Ident); ok && qualifier != "" && x.Name == qualifier {
					mark(node.Sel.Name)
					return false
				}
				if samePackage {
					ast.Inspect(node.X, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							mark(id.Name)
						}
						return true
					})
				}
				return false
			case *ast.Ident:
				if samePackage {
					mark(node.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	var dead []string
	for name, value := range values {
		if referenced[name] || registry[value] {
			continue
		}
		if _, ok := exempt[name]; ok {
			continue
		}
		dead = append(dead, name)
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Fatalf("%d authhttp.ErrorCode consts are never emitted (#290) — delete them, or exempt with a reason:\n  %s",
			len(dead), strings.Join(dead, "\n  "))
	}
}
