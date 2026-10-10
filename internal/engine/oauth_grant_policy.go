package engine

// The host's say in the jwt-bearer grant (#437): the grant authorizer
// (Deps.OAuthGrants) may refuse or narrow a workload's capability.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/helpers/auth"
)

// maxGrantClaimsBytes bounds the host's extra access-token claims.
const maxGrantClaimsBytes = 8 << 10

// errOAuthGrantRefused marks the host authorizer's refusal, or a grant
// whose end has passed; the caller maps it to the protocol's answer.
var errOAuthGrantRefused = errors.New("authkit: oauth: the grant authorizer refused the grant")

// decideOAuthGrant asks the host authorizer for req and checks its
// decision: its authorization_details may only narrow the capability's,
// using the client's declared types. A refusal is errOAuthGrantRefused; any
// other failure is an outage.
func (s *Engine) decideOAuthGrant(ctx context.Context, req iam.OAuthGrantRequest, detailTypes []string) (*authflow.OAuthGrantDecision, error) {
	if s.oauthGrants == nil {
		return nil, errors.New("authkit: oauth: the jwt-bearer grant needs a grant authorizer")
	}
	d, err := s.oauthGrants(ctx, req)
	switch {
	case errors.Is(err, iam.ErrOAuthGrantRefused):
		return nil, errOAuthGrantRefused
	case err != nil:
		return nil, fmt.Errorf("authkit: oauth: grant authorizer: %w", err)
	}
	out := &authflow.OAuthGrantDecision{MaxLifetime: d.MaxLifetime, AuthorizationDetails: req.AuthorizationDetails, Invoker: d.Invoker}
	if d.MaxLifetime < 0 || d.MaxLifetime > 0 && d.MaxLifetime < time.Second {
		return nil, errors.New("authkit: oauth: grant authorizer MaxLifetime must be 0 or at least a second")
	}
	if d.AuthorizationDetails != nil {
		compact, oerr := authflow.ParseAuthorizationDetails(string(d.AuthorizationDetails), detailTypes)
		if oerr != nil {
			return nil, fmt.Errorf("authkit: oauth: grant authorizer returned invalid authorization_details: %s", oerr.Description)
		}
		out.AuthorizationDetails = compact
	}
	if len(d.Claims) > 0 {
		if err := checkGrantClaims(d.Claims); err != nil {
			return nil, err
		}
		out.Claims = d.Claims
	}
	if out.Invoker == "" {
		out.Invoker = req.JWKThumbprint
	}
	switch {
	case !authflow.NarrowsAuthorizationDetails(req.AuthorizationDetails, out.AuthorizationDetails):
		return nil, errors.New("authkit: oauth: grant authorizer may only narrow a capability's authorization_details: each entry must be one of the capability's")
	case !validActor(out.Invoker):
		return nil, errors.New("authkit: oauth: grant authorizer Invoker must be 1-256 printable characters without spaces")
	}
	return out, nil
}

// validActor is an act.sub: 1-256 printable bytes without spaces.
func validActor(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// checkGrantClaims refuses an extra claim whose name is not an absolute URI
// (RFC 7519 §4.2 collision resistance) or whose value does not encode.
func checkGrantClaims(claims map[string]any) error {
	for name := range claims {
		u, err := url.Parse(name)
		if err != nil || !u.IsAbs() || u.Host == "" || strings.ContainsAny(name, " \t\n") {
			return fmt.Errorf("authkit: oauth: grant authorizer claim %q must be named by an absolute URI", name)
		}
	}
	raw, err := json.Marshal(claims)
	switch {
	case err != nil:
		return fmt.Errorf("authkit: oauth: grant authorizer claims do not encode: %w", err)
	case len(raw) > maxGrantClaimsBytes:
		return errors.New("authkit: oauth: grant authorizer claims are too large")
	}
	return nil
}

// grantPermissions is what m's access token carries: the user's live root
// grants (a client's own for client credentials) within the resource's
// ceiling; none for a workload.
func (s *Engine) grantPermissions(ctx context.Context, m oauthMint, ceiling []string) ([]string, error) {
	if len(ceiling) == 0 || m.workload {
		return []string{}, nil
	}
	if m.userID == "" {
		return nonNil(intersectGrants(m.client.Permissions, ceiling)), nil
	}
	auth, err := s.rootAuthority(ctx, iam.InSession(iam.UserIdentity(m.userID), iam.SessionRef{SessionID: m.sessionID}))
	if err != nil {
		return nil, err
	}
	return nonNil(intersectGrants(auth.grants, ceiling)), nil
}

// rootAuthority is a's authority on the root group (rule IDENTITY).
func (s *Engine) rootAuthority(ctx context.Context, a auth.Identity) (authority, error) {
	if err := s.requirePG(); err != nil {
		return authority{}, err
	}
	st := s.groupStore()
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return authority{}, err
	}
	return s.identityAuthority(ctx, st, a, groupTarget{ID: rootID, Persona: iam.RootPersona()})
}

func nonNil(perms []string) []string {
	if perms == nil {
		return []string{}
	}
	return perms
}
