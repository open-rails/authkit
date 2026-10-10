package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/verify"
)

// The resource server (Config.Resource) verifies the RFC 9068 access tokens
// minted for Resource.ID: this deployment's own authorization server's, and
// its trusted issuers', the enabled remote applications of live groups. Each
// token is validated per RFC 9068 §4 (typ at+jwt, iss, aud, signature,
// times) and presented per RFC 6750 or, when bound (cnf.jkt), RFC 9449 with
// a proof and a server nonce. A trusted issuer's token acts within its
// application's group; its keys come from the registry, read live, so a
// disabled application's tokens stop on the next request.

// ResourceAccess is a verified access token for Config.Resource.ID.
type ResourceAccess struct {
	Claims verify.Claims
	// Application is the remote application the token acts through: the
	// trusted issuer that minted it, or the one whose assertion this
	// deployment redeemed for it (Asserted, RFC 7523). Nil for this
	// deployment's own users and clients.
	Application *iam.RemoteApplication
	// Asserted is a token this deployment minted for an application's user
	// (OAuthRemoteAssertion): its sub is in the application's namespace.
	Asserted bool
	// Permissions are what a trusted issuer's token carries: its
	// permissions claim and the grants of the roles its roles claim maps to
	// (RoleMap). Its application's role bounds them.
	Permissions []string
	// Ceilings are the permission ceilings the token's scopes grant
	// (Config.Resource.Scopes); nil when no scope ceiling applies.
	Ceilings []iam.Perm
	Scoped   bool
}

// Group is the group the token is bound to: its application's.
func (a ResourceAccess) Group() string {
	if a.Application == nil {
		return ""
	}
	return a.Application.GroupID
}

type resourceServer struct {
	s *Engine
	v *verify.Verifier
	// assertions verifies trusted issuers' RFC 7523 assertions, whose aud
	// is the token endpoint.
	assertions *verify.Verifier
	// metadata fetches issuer metadata (RFC 8414) for applications without
	// a jwks_uri, through the same guarded client as their keys.
	metadata *http.Client

	mu sync.Mutex
	// registered is when each trusted issuer's keys were last given to v:
	// its application's UpdatedAt.
	registered map[string]time.Time
}

func (s *Engine) newResourceServer() (*resourceServer, error) {
	rc := s.cfg.Resource
	client := netguard.Client(netguard.DefaultTimeout, s.cfg.Token.AllowPrivateNetworkJWKS)
	opts := []verify.VerifierOption{
		verify.WithHTTPClient(client),
		verify.WithDPoP(s.redis),
		verify.WithStoredDPoPNonces(),
		verify.WithPublicURL(rc.PublicURL),
	}
	if s.resourceHosts != nil {
		opts = append(opts, verify.WithPublicHosts(s.resourceHosts))
	}
	rs := &resourceServer{s: s, v: verify.NewVerifier(opts...), assertions: verify.NewVerifier(verify.WithHTTPClient(client)), metadata: client, registered: map[string]time.Time{}}
	if err := rs.v.AddIssuer(s.cfg.Token.Issuer, []string{rc.ID}, verify.IssuerOptions{KeySource: s.keys, IsLocal: true}); err != nil {
		return nil, err
	}
	return rs, nil
}

// ResourceEnabled reports whether Config.Resource admits access tokens.
func (s *Engine) ResourceEnabled() bool { return s.resource != nil }

// VerifyResourceRequest verifies r's access token for Config.Resource.ID.
// Its errors are verify's, for verify.Refusal.
func (s *Engine) VerifyResourceRequest(r *http.Request) (ResourceAccess, error) {
	if s.resource == nil {
		return ResourceAccess{}, errmodel.E(errmodel.CodeUnsupportedTokenTyp)
	}
	return s.resource.verify(r)
}

func (rs *resourceServer) verify(r *http.Request) (ResourceAccess, error) {
	ctx := r.Context()
	token, _ := jose.RequestToken(r)
	if token == "" {
		return ResourceAccess{}, errmodel.E(errmodel.CodeUnauthenticated)
	}
	typ, unverified, ok := jose.Unverified(token)
	if !ok || !resourceTokenType(typ) {
		return ResourceAccess{}, errmodel.E(errmodel.CodeUnsupportedTokenTyp)
	}
	var out ResourceAccess
	if iss := jose.String(unverified, "iss"); iss != rs.s.cfg.Token.Issuer {
		app, err := rs.trusted(ctx, iss)
		if err != nil {
			return ResourceAccess{}, err
		}
		out.Application = app
	}
	cl, err := rs.v.VerifyRequest(r)
	if err != nil {
		return ResourceAccess{}, err
	}
	if !cl.IsResourceToken() || strings.TrimSpace(cl.Subject) == "" {
		return ResourceAccess{}, errmodel.E(errmodel.CodeInvalidToken)
	}
	out.Claims = cl
	if out.Application == nil {
		if out.Application, err = rs.ownToken(ctx, cl); err != nil {
			return ResourceAccess{}, err
		}
		out.Asserted = out.Application != nil
	}
	if app := out.Application; app != nil {
		out.Permissions = append([]string(nil), cl.Permissions...)
		for _, name := range cl.Roles {
			if role, ok := app.RoleMap[name]; ok {
				grants, err := rs.s.roleGrants(ctx, rs.s.pg, groupTarget{ID: app.GroupID, Persona: role.Persona()}, role)
				switch {
				case err == nil:
					out.Permissions = append(out.Permissions, grants...)
				case !errors.Is(err, iam.ErrRoleNotAssignable):
					return ResourceAccess{}, errmodel.Internal("resource_role_map", err)
				}
			}
		}
		if cl.Kind == verify.TokenUser {
			granted, err := rs.s.remoteUserGrants(ctx, app.GroupID, app.Issuer, cl.Subject)
			if err != nil {
				return ResourceAccess{}, errmodel.Internal("resource_remote_user_role", err)
			}
			out.Permissions = append(out.Permissions, granted...)
		}
	}
	out.Ceilings, out.Scoped = rs.ceilings(cl.Scopes)
	return out, nil
}

// trusted is the enabled remote application of a live group whose issuer is
// iss, its keys given to the verifier.
func (rs *resourceServer) trusted(ctx context.Context, iss string) (*iam.RemoteApplication, error) {
	if iss == "" {
		return nil, errmodel.E(errmodel.CodeBadIssuer)
	}
	app, err := rs.s.GetRemoteApplication(ctx, iss)
	switch {
	case errors.Is(err, iam.ErrRemoteApplicationNotFound), errors.Is(err, iam.ErrInvalidRemoteApplication):
		return nil, errmodel.E(errmodel.CodeBadIssuer)
	case err != nil:
		return nil, errmodel.Internal("resource_issuer", err)
	}
	if err := rs.register(ctx, *app); err != nil {
		return nil, err
	}
	return app, nil
}

// register gives the verifier app's current keys: its static keys, its
// jwks_uri, or the jwks_uri of its RFC 8414 metadata.
func (rs *resourceServer) register(ctx context.Context, app iam.RemoteApplication) error {
	rs.mu.Lock()
	at, done := rs.registered[app.Issuer]
	rs.mu.Unlock()
	if done && at.Equal(app.UpdatedAt) {
		return nil
	}
	keys := verify.IssuerOptions{Keys: app.PublicKeys}
	if app.Mode == iam.RemoteApplicationModeJWKS || len(app.PublicKeys) == 0 {
		uri := app.JWKSURI
		if uri == "" {
			var err error
			if uri, err = rs.discover(ctx, app.Issuer); err != nil {
				return errmodel.E(errmodel.CodeIssuerKeysUnavailable, errmodel.WithCause(err))
			}
		}
		keys = verify.IssuerOptions{JWKSURI: uri}
	}
	if err := rs.v.AddIssuer(app.Issuer, []string{rs.s.cfg.Resource.ID}, keys); err != nil {
		return errmodel.Internal("resource_issuer_keys", err)
	}
	if endpoint := rs.s.oauthTokenEndpoint(); endpoint != "" {
		if err := rs.assertions.AddIssuer(app.Issuer, []string{endpoint}, keys); err != nil {
			return errmodel.Internal("resource_issuer_keys", err)
		}
	}
	rs.mu.Lock()
	rs.registered[app.Issuer] = app.UpdatedAt
	rs.mu.Unlock()
	return nil
}

// discover reads issuer's jwks_uri from its authorization server metadata
// (RFC 8414 §3), else its OpenID Provider metadata; the metadata must name
// issuer itself (RFC 8414 §3.3).
func (rs *resourceServer) discover(ctx context.Context, issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("issuer %q is not a URL", issuer)
	}
	oauth := *u
	oauth.Path = "/.well-known/oauth-authorization-server" + strings.TrimRight(u.Path, "/")
	var lastErr error
	for _, metadata := range []string{oauth.String(), strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"} {
		uri, err := rs.jwksURI(ctx, issuer, metadata)
		if err == nil {
			return uri, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (rs *resourceServer) jwksURI(ctx context.Context, issuer, metadata string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, netguard.DefaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata, nil)
	if err != nil {
		return "", err
	}
	res, err := rs.metadata.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", metadata, res.StatusCode)
	}
	var m struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&m); err != nil {
		return "", fmt.Errorf("%s: %w", metadata, err)
	}
	if m.Issuer != issuer {
		return "", fmt.Errorf("%s names issuer %q", metadata, m.Issuer)
	}
	if err := validateJWKSURI(m.JWKSURI, rs.s.cfg.Token.AllowPrivateNetworkJWKS); err != nil {
		return "", fmt.Errorf("%s: %w", metadata, err)
	}
	return m.JWKSURI, nil
}

// ownToken checks a token of this deployment's authorization server: issued
// to a registered client, and for a user, on a sign-in that still stands;
// or redeemed for a trusted application's user (OAuthRemoteAssertion), whose
// application, named by client_id, must still be trusted.
func (rs *resourceServer) ownToken(ctx context.Context, cl verify.Claims) (*iam.RemoteApplication, error) {
	if _, ok := config.FindOAuthClient(rs.s.cfg.AuthorizationServer, cl.ClientID); !ok {
		app, err := rs.trusted(ctx, cl.ClientID)
		if err != nil || cl.Kind != verify.TokenUser {
			return nil, errmodel.E(errmodel.CodeInvalidToken)
		}
		return app, nil
	}
	if cl.Kind != verify.TokenUser {
		return nil, nil
	}
	if err := rs.s.requirePG(); err != nil {
		return nil, err
	}
	ref := iam.SessionRef{SessionID: cl.SessionID, DeviceKeyID: cl.DeviceKeyID}
	if ref.IsZero() {
		return nil, iam.ErrSessionRevoked
	}
	usable, signedIn, err := userLive(ctx, rs.s.pg, cl.Subject, ref)
	switch {
	case err != nil:
		return nil, errmodel.Internal("resource_session", err)
	case !usable || !signedIn:
		return nil, iam.ErrSessionRevoked
	}
	return nil, nil
}

// ceilings are the permission ceilings scopes grant, when Resource.Scopes
// declares any: a scope not declared grants none.
func (rs *resourceServer) ceilings(scopes []string) ([]iam.Perm, bool) {
	declared := rs.s.cfg.Resource.Scopes
	if len(declared) == 0 {
		return nil, false
	}
	out := []iam.Perm{}
	for _, scope := range scopes {
		for _, p := range declared[scope] {
			out = append(out, ident.Perm(p))
		}
	}
	return out, true
}

func resourceTokenType(typ string) bool {
	return strings.EqualFold(typ, jose.ResourceAccessTokenType) || strings.EqualFold(typ, "application/"+jose.ResourceAccessTokenType)
}
