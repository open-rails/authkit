package engine

// The host's say in the authorization server's grants (#433): the grant
// authorizer (Deps.OAuthGrants) decides consent, token exchange, client
// credentials and every refresh; RFC 9396 authorization_details carry
// structured grants; RevokeOAuthGrant ends a consented grant.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/helpers/auth"
)

const (
	keyOAuthGrant = "oauth:grant:" // +grant id → the refresh family's key
	// +user id → when the account's offline grants were all ended
	keyOAuthOfflineEnded = "oauth:offline-ended:"

	// maxGrantClaimsBytes bounds the host's extra access-token claims.
	maxGrantClaimsBytes = 8 << 10
)

// errOAuthGrantRefused marks the host authorizer's refusal; the caller maps
// it to the protocol's answer.
var errOAuthGrantRefused = errors.New("authkit: oauth: the grant authorizer refused the grant")

// decideOAuthGrant asks the host authorizer for req and checks its
// decision: its authorization_details may use only the client's declared
// types. Without an authorizer it returns nil: the defaults. A refusal is
// errOAuthGrantRefused; any other failure is an outage.
func (s *Engine) decideOAuthGrant(ctx context.Context, req iam.OAuthGrantRequest, detailTypes []string) (*authflow.OAuthGrantDecision, error) {
	if s.oauthGrants == nil {
		if len(req.AuthorizationDetails) > 0 {
			return nil, errors.New("authkit: oauth: authorization_details without a grant authorizer")
		}
		return nil, nil
	}
	d, err := s.oauthGrants(ctx, req)
	switch {
	case errors.Is(err, iam.ErrOAuthGrantRefused):
		return nil, errOAuthGrantRefused
	case err != nil:
		return nil, fmt.Errorf("authkit: oauth: grant authorizer: %w", err)
	}
	out := &authflow.OAuthGrantDecision{Permissions: d.Permissions, MaxLifetime: d.MaxLifetime, AuthorizationDetails: req.AuthorizationDetails}
	if d.MaxLifetime < 0 || d.MaxLifetime > 0 && d.MaxLifetime < time.Second {
		return nil, errors.New("authkit: oauth: grant authorizer MaxLifetime must be 0 or at least a second")
	}
	for _, perm := range d.Permissions {
		if err := ident.ValidateGrantPattern(perm); err != nil {
			return nil, fmt.Errorf("authkit: oauth: grant authorizer permission %q: %w", perm, err)
		}
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
	return out, nil
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

// oauthGrantFailure answers a token request whose decision failed: a
// refusal as code (invalid_grant, or unauthorized_client for a client acting
// for itself), an outage as temporarily_unavailable.
func oauthGrantFailure(err error, code string) error {
	if errors.Is(err, errOAuthGrantRefused) {
		return authflow.NewOAuthError(code, "the grant was refused")
	}
	return &authflow.OAuthError{Code: authflow.OAuthTemporarilyUnavailable, Description: "the grant cannot be decided now; retry later", Status: 503}
}

// grantPermissions is what m's access token carries: the authorizer's
// permissions or the defaults (the user's live root grants, a client's own),
// within the resource's ceiling. An authorizer permission in an AuthKit
// persona's namespace the user does not hold now refuses the grant.
func (s *Engine) grantPermissions(ctx context.Context, m oauthMint, ceiling []string) ([]string, error) {
	if len(ceiling) == 0 {
		return []string{}, nil
	}
	if m.userID == "" {
		held := m.client.Permissions
		if m.decision != nil && m.decision.Permissions != nil {
			held = m.decision.Permissions
		}
		return nonNil(intersectGrants(held, ceiling)), nil
	}
	who := iam.UserIdentity(m.userID)
	if !m.offline {
		who = iam.InSession(who, iam.SessionRef{SessionID: m.sessionID, DeviceKeyID: m.deviceKeyID})
	}
	auth, err := s.rootAuthority(ctx, who)
	if err != nil {
		return nil, err
	}
	if m.decision == nil || m.decision.Permissions == nil {
		return nonNil(intersectGrants(auth.grants, ceiling)), nil
	}
	for _, perm := range m.decision.Permissions {
		if !s.grantPermissionHeld(auth, perm) {
			return nil, errOAuthGrantRefused
		}
	}
	return nonNil(intersectGrants(m.decision.Permissions, ceiling)), nil
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

// grantPermissionHeld is whether a grant may carry perm for auth: the
// host's own vocabulary is the host's decision; a permission in an AuthKit
// persona's namespace must be held live.
func (s *Engine) grantPermissionHeld(auth authority, perm string) bool {
	namespace, _, _ := strings.Cut(perm, ":")
	sch := s.groupSchemaOrDefault()
	if _, ok := sch.PersonaNamed(namespace); !ok && namespace != "*" {
		return true
	}
	p, known := sch.Permission(perm)
	return known && auth.covers(p)
}

func nonNil(perms []string) []string {
	if perms == nil {
		return []string{}
	}
	return perms
}

// RevokeOAuthGrant ends a consented grant (its id from the grant
// authorizer's request): its refresh tokens stop working at once; access
// tokens already minted expire on their own. An unknown or ended grant is
// not an error.
func (s *Engine) RevokeOAuthGrant(ctx context.Context, grantID string, opts ...ops.Option) error {
	if err := noOptions("RevokeOAuthGrant", opts); err != nil {
		return err
	}
	grantID = strings.TrimSpace(grantID)
	if !isUUID(grantID) {
		return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("grant_id"))
	}
	if s.ephemeral == nil {
		return s.requirePG()
	}
	var familyKey string
	_, found, err := s.ephemReadJSON(ctx, keyOAuthGrant+grantID, &familyKey)
	if err != nil || !found {
		return err
	}
	var f oauthRefreshFamily
	if _, ok, err := s.ephemReadJSON(ctx, familyKey, &f); err != nil {
		return err
	} else if ok && f.GrantID == grantID {
		if err := s.ephemeral.Del(ctx, familyKey); err != nil {
			return err
		}
		s.oauthAudit(ctx, "oauth_grant_revoked", f.UserID, map[string]string{"client_id": f.ClientID, "grant_id": grantID})
	}
	return s.ephemeral.Del(ctx, keyOAuthGrant+grantID)
}

// endOfflineGrants ends every offline grant of userID minted until now.
func (s *Engine) endOfflineGrants(ctx context.Context, userID string) error {
	if s.ephemeral == nil {
		return nil
	}
	return s.ephemSetJSON(ctx, keyOAuthOfflineEnded+userID, s.nowTime().UTC(), config.MaxOAuthRefreshTokenTTL)
}

// grantExpiry is when a grant started at created ends: its family's
// lifetime, capped by the decision's MaxLifetime.
func grantExpiry(created, familyEnd time.Time, d *authflow.OAuthGrantDecision) time.Time {
	if d != nil && d.MaxLifetime > 0 && !created.IsZero() {
		if capped := created.Add(d.MaxLifetime); capped.Before(familyEnd) {
			return capped
		}
	}
	return familyEnd
}
