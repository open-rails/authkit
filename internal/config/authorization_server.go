package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// AuthorizationServerConfig declares the OAuth clients this deployment signs
// users in for and the resource servers it mints access tokens for. Clients
// and resources are configuration only: there is no dynamic registration.
// Every client is first-party: a signed-in user is never asked to consent.
type AuthorizationServerConfig struct {
	// Clients are the registered OAuth clients. None leaves the
	// authorization server off.
	Clients []OAuthClientConfig `yaml:"clients"`
	// Resources are the resource servers access tokens may be minted for
	// (RFC 8707 resource indicators).
	Resources []ResourceServerConfig `yaml:"resources"`
	// AccessTokenTTL is the lifetime of the RFC 9068 access tokens it mints.
	// 0 defaults to 5 minutes, the most allowed.
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`
	// RefreshTokenTTL bounds a refresh token family: rotation never extends
	// it, and the client signs the user in again (prompt=none) after it.
	// 0 defaults to 12 hours; at most 30 days. A family also ends with the
	// sign-in it was issued from.
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
	// GroupClients is the policy for the OAuth clients groups register at
	// run time (personas declared with OAuthClients): third-party clients
	// whose users consent to each scope.
	GroupClients GroupClientsConfig `yaml:"group_clients"`

	// groupClients: some persona registers group clients, so the
	// authorization server is on (Normalize).
	groupClients bool
}

// GroupClientsConfig is what a group's OAuth client may ask of a user.
type GroupClientsConfig struct {
	// Scopes are the scopes a group client may request beyond OpenID's
	// (openid, email, phone, profile), each for one resource, with the
	// description the consent screen shows.
	Scopes []GroupClientScope `yaml:"scopes"`
	// Agreements are keys of Config.Agreements a user accepts, at their
	// current versions, before approving any group client.
	Agreements []string `yaml:"agreements"`
}

// GroupClientScope is one scope a group client may request.
type GroupClientScope struct {
	// Name is the scope; one of Resource's Scopes.
	Name string `yaml:"name"`
	// Resource is the resource server (ResourceServerConfig.ID) a token
	// carrying it is for.
	Resource string `yaml:"resource"`
	// Description says what consenting allows, on the consent screen.
	Description string `yaml:"description"`
}

// OAuthClientConfig registers one OAuth client.
type OAuthClientConfig struct {
	// ID is the client_id: 1-128 characters of letters, digits, '.', '_',
	// '-' and ':'.
	ID string `yaml:"id"`
	// Name is shown to the user while they sign in for it; empty uses ID.
	Name string `yaml:"name"`
	// SecretSHA256 makes the client confidential: the lowercase hex SHA-256
	// of its secret, which must be at least 32 random bytes. AuthKit never
	// holds the secret. Empty makes the client public (a browser or native
	// app, or a fleet of workloads using the jwt-bearer grant), which must
	// use DPoP and cannot use client credentials.
	SecretSHA256 string `yaml:"secret_sha256"`
	// RedirectURIs are the exact redirect_uri values the client may use:
	// absolute https URLs, or http on a loopback host, without a fragment.
	RedirectURIs []string `yaml:"redirect_uris"`
	// PostLogoutRedirectURIs are the exact post_logout_redirect_uri values
	// RP-initiated logout may return to; the same rules apply.
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	// GrantTypes are the grants the client may use. Empty allows
	// authorization_code.
	GrantTypes []OAuthGrantType `yaml:"grant_types"`
	// Resources are the resource identifiers (ResourceServerConfig.ID) the
	// client may request tokens for. A request names one with the resource
	// parameter; with none, the access token is good for userinfo only.
	Resources []string `yaml:"resources"`
	// Permissions are a client-credentials client's own grants, as grant
	// patterns: its tokens carry them within the resource's ceiling.
	Permissions []string `yaml:"permissions"`
	// Origins are browser origins ("https://admin.example.com") the client
	// calls the token endpoint from, besides its redirect URIs' origins: a
	// host frontend using token exchange.
	Origins []string `yaml:"origins"`
	// AuthorizationDetailsTypes are the RFC 9396 authorization_details types
	// a jwt-bearer client's capabilities may carry ("hub_operation"). The
	// host's grant authorizer (Deps.OAuthGrants) decides each grant, so
	// declaring any needs one.
	AuthorizationDetailsTypes []string `yaml:"authorization_details_types"`
	// Agreements are keys of Config.Agreements a user accepts, at their
	// current versions, before approving the client's sign-in: approval
	// answers agreement_required until they do.
	Agreements []string `yaml:"agreements"`
}

// ResourceServerConfig registers one resource server: an API that accepts
// this deployment's RFC 9068 access tokens.
type ResourceServerConfig struct {
	// ID is the resource identifier, the access token's aud: an absolute URI
	// without a fragment, usually the API's base URL.
	ID string `yaml:"id"`
	// Scopes are the OAuth scopes the resource defines; a client may request
	// any of them for it.
	Scopes []string `yaml:"scopes"`
	// Permissions is the resource's permission ceiling, as grant patterns in
	// its own namespace ("merchant:*", "merchant:subscriptions:update"). An
	// access token for it carries, as permissions, the user's live grants on
	// the root group (what this deployment's roles assign them) intersected
	// with this ceiling, so the resource server authorizes from the token.
	// Empty mints tokens with no permissions.
	Permissions []string `yaml:"permissions"`
	// ContactClaims puts the user's contact in every access token for the
	// resource, whatever scopes it carries: the OIDC claims email and
	// email_verified, preferred_username, name and updated_at (seconds since
	// the epoch, when one of them last changed). A resource that keeps its
	// own copy of who a user is learns a new user from the first request.
	// Other resources' tokens carry only what their scopes grant.
	ContactClaims bool `yaml:"contact_claims"`
}

// OAuthGrantType is an OAuth 2.0 grant type a client may use.
type OAuthGrantType string

const (
	// GrantAuthorizationCode is the authorization code grant with PKCE.
	GrantAuthorizationCode OAuthGrantType = "authorization_code"
	// GrantRefreshToken issues rotating refresh tokens with the code grant.
	GrantRefreshToken OAuthGrantType = "refresh_token"
	// GrantTokenExchange is RFC 8693 token exchange: a frontend trades the
	// user's AuthKit access token for a resource's access token.
	GrantTokenExchange OAuthGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// GrantClientCredentials is a confidential client acting for itself.
	GrantClientCredentials OAuthGrantType = "client_credentials"
	// GrantJWTBearer is the RFC 7523 JWT-bearer grant: a workload's key
	// signs an assertion carrying a capability one of the user's device keys
	// signed for it, and proves itself with DPoP.
	GrantJWTBearer OAuthGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// DefaultOAuthAccessTokenTTL is AuthorizationServerConfig.AccessTokenTTL's
// default and ceiling.
const DefaultOAuthAccessTokenTTL = 5 * time.Minute

// DefaultOAuthRefreshTokenTTL is AuthorizationServerConfig.RefreshTokenTTL's
// default; MaxOAuthRefreshTokenTTL its ceiling.
const (
	DefaultOAuthRefreshTokenTTL = 12 * time.Hour
	MaxOAuthRefreshTokenTTL     = 30 * 24 * time.Hour
)

// oidcScopes are the scopes AuthKit defines itself; a resource may not
// redefine one.
var oidcScopes = []string{"openid", "profile", "email", "phone", "offline_access"}

var (
	clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	// uuidPattern: a client ID shaped like a user ID would make a client
	// credentials token's sub ambiguous.
	uuidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{12}$`)
	// RFC 6749 §3.3 scope-token, minus the quote and backslash.
	scopePattern = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,128}$`)
)

// AuthorizationServerEnabled reports whether the authorization server is on.
func AuthorizationServerEnabled(a AuthorizationServerConfig) bool {
	return len(a.Clients) > 0 || a.groupClients
}

// GroupClientsEnabled reports whether some persona registers group OAuth
// clients.
func GroupClientsEnabled(a AuthorizationServerConfig) bool { return a.groupClients }

// GroupClientIDPrefix starts every group client's id; a declared client's id
// never does.
const GroupClientIDPrefix = "goc_"

// FindGroupClientScope returns the group-client scope named name.
func FindGroupClientScope(a AuthorizationServerConfig, name string) (GroupClientScope, bool) {
	for _, s := range a.GroupClients.Scopes {
		if s.Name == name {
			return s, true
		}
	}
	return GroupClientScope{}, false
}

// FindOAuthClient returns the registered client with id.
func FindOAuthClient(a AuthorizationServerConfig, id string) (OAuthClientConfig, bool) {
	for _, c := range a.Clients {
		if c.ID == id {
			return c, true
		}
	}
	return OAuthClientConfig{}, false
}

// FindResourceServer returns the registered resource server with id.
func FindResourceServer(a AuthorizationServerConfig, id string) (ResourceServerConfig, bool) {
	for _, r := range a.Resources {
		if r.ID == id {
			return r, true
		}
	}
	return ResourceServerConfig{}, false
}

// OAuthClientConfidential reports whether c authenticates with a secret.
func OAuthClientConfidential(c OAuthClientConfig) bool { return c.SecretSHA256 != "" }

// OAuthClientAllows reports whether c may use grant.
func OAuthClientAllows(c OAuthClientConfig, grant OAuthGrantType) bool {
	return slices.Contains(c.GrantTypes, grant)
}

// SCIMReadScope is the scope a client-credentials token needs to read the
// SCIM service provider.
const SCIMReadScope = "scim:read"

// SCIMResource is the SCIM service provider beneath issuer: its base URL,
// and the resource a client lists to get tokens for it.
func SCIMResource(issuer string) string { return strings.TrimRight(issuer, "/") + "/scim/v2" }

// OIDCScope reports whether scope is one AuthKit itself defines.
func OIDCScope(scope string) bool { return slices.Contains(oidcScopes, scope) }

func normalizeAuthorizationServer(a *AuthorizationServerConfig, c Config) error {
	a.groupClients = c.Roles != nil && c.Roles.oauthClients()
	if len(a.Clients) == 0 && !a.groupClients {
		if len(a.Resources) > 0 || a.AccessTokenTTL != 0 || a.RefreshTokenTTL != 0 || len(a.GroupClients.Scopes) > 0 || len(a.GroupClients.Agreements) > 0 {
			return errors.New("authkit: AuthorizationServer has resources, a TTL or group-client policy but no Clients and no persona with OAuthClients — the authorization server is off")
		}
		return nil
	}
	if c.HTTP == nil {
		return errors.New("authkit: AuthorizationServer needs Config.HTTP: its endpoints are part of the HTTP surface")
	}
	if !isURL(c.Token.Issuer) {
		return fmt.Errorf("authkit: AuthorizationServer needs Token.Issuer to be an absolute URL (issuer=%q)", c.Token.Issuer)
	}
	switch {
	case a.AccessTokenTTL < 0 || a.AccessTokenTTL > DefaultOAuthAccessTokenTTL:
		return fmt.Errorf("authkit: AuthorizationServer.AccessTokenTTL must be between 0 and %v, got %v", DefaultOAuthAccessTokenTTL, a.AccessTokenTTL)
	case a.AccessTokenTTL == 0:
		a.AccessTokenTTL = DefaultOAuthAccessTokenTTL
	}
	switch {
	case a.RefreshTokenTTL < 0 || a.RefreshTokenTTL > MaxOAuthRefreshTokenTTL:
		return fmt.Errorf("authkit: AuthorizationServer.RefreshTokenTTL must be between 0 and %v, got %v", MaxOAuthRefreshTokenTTL, a.RefreshTokenTTL)
	case a.RefreshTokenTTL == 0:
		a.RefreshTokenTTL = DefaultOAuthRefreshTokenTTL
	}

	resources := make([]ResourceServerConfig, 0, len(a.Resources))
	for i, r := range a.Resources {
		r.ID = strings.TrimSpace(r.ID)
		if err := validResourceID(r.ID); err != nil {
			return fmt.Errorf("authkit: AuthorizationServer.Resources[%d]: %w", i, err)
		}
		if slices.ContainsFunc(resources, func(o ResourceServerConfig) bool { return o.ID == r.ID }) {
			return fmt.Errorf("authkit: AuthorizationServer.Resources[%d]: resource %q is declared twice", i, r.ID)
		}
		scopes, err := normalizeScopes(r.Scopes)
		if err != nil {
			return fmt.Errorf("authkit: AuthorizationServer.Resources[%d] (%s): %w", i, r.ID, err)
		}
		r.Scopes = scopes
		if r.Permissions, err = normalizeResourcePermissions(r.Permissions); err != nil {
			return fmt.Errorf("authkit: AuthorizationServer.Resources[%d] (%s): %w", i, r.ID, err)
		}
		resources = append(resources, r)
	}
	scim := ResourceServerConfig{ID: SCIMResource(c.Token.Issuer), Scopes: []string{SCIMReadScope}}
	if i := slices.IndexFunc(resources, func(r ResourceServerConfig) bool { return r.ID == scim.ID }); i >= 0 {
		// Normalized once already, or declared by hand.
		if r := resources[i]; !slices.Equal(r.Scopes, scim.Scopes) || len(r.Permissions) > 0 || r.ContactClaims {
			return fmt.Errorf("authkit: AuthorizationServer.Resources: %q is AuthKit's own SCIM service provider; clients name it without declaring it", scim.ID)
		}
		resources = slices.Delete(resources, i, i+1)
	}
	a.Resources = append(resources, scim)

	clients := make([]OAuthClientConfig, 0, len(a.Clients))
	for i, cl := range a.Clients {
		if err := normalizeOAuthClient(&cl, a.Resources); err != nil {
			return fmt.Errorf("authkit: AuthorizationServer.Clients[%d]: %w", i, err)
		}
		if OAuthClientAllows(cl, GrantJWTBearer) && !c.DeviceKeys.Enabled {
			return fmt.Errorf("authkit: AuthorizationServer.Clients[%d]: client %q: the jwt-bearer grant needs DeviceKeys.Enabled: device keys sign its capabilities", i, cl.ID)
		}
		if slices.ContainsFunc(clients, func(o OAuthClientConfig) bool { return o.ID == cl.ID }) {
			return fmt.Errorf("authkit: AuthorizationServer.Clients[%d]: client %q is declared twice", i, cl.ID)
		}
		if strings.HasPrefix(cl.ID, GroupClientIDPrefix) {
			return fmt.Errorf("authkit: AuthorizationServer.Clients[%d]: client ids starting %q are groups' clients", i, GroupClientIDPrefix)
		}
		cl.Agreements = dedup(cl.Agreements)
		for _, key := range cl.Agreements {
			if !slices.ContainsFunc(c.Agreements, func(a AgreementConfig) bool { return a.Key == key }) {
				return fmt.Errorf("authkit: AuthorizationServer.Clients[%d]: client %q names agreement %q, which Agreements does not declare", i, cl.ID, key)
			}
		}
		clients = append(clients, cl)
	}
	a.Clients = clients
	return normalizeGroupClients(&a.GroupClients, a.Resources, c.Agreements)
}

// normalizeGroupClients checks each group-client scope names a resource
// that defines it, and each agreement a declared document.
func normalizeGroupClients(g *GroupClientsConfig, resources []ResourceServerConfig, agreements []AgreementConfig) error {
	scopes := make([]GroupClientScope, 0, len(g.Scopes))
	for i, sc := range g.Scopes {
		sc.Name, sc.Resource, sc.Description = strings.TrimSpace(sc.Name), strings.TrimSpace(sc.Resource), strings.TrimSpace(sc.Description)
		r, ok := FindResourceServer(AuthorizationServerConfig{Resources: resources}, sc.Resource)
		switch {
		case !ok || !slices.Contains(r.Scopes, sc.Name):
			return fmt.Errorf("authkit: AuthorizationServer.GroupClients.Scopes[%d]: scope %q must be one of resource %q's Scopes", i, sc.Name, sc.Resource)
		case sc.Description == "":
			return fmt.Errorf("authkit: AuthorizationServer.GroupClients.Scopes[%d]: scope %q needs the description its consent screen shows", i, sc.Name)
		case slices.ContainsFunc(scopes, func(o GroupClientScope) bool { return o.Name == sc.Name }):
			return fmt.Errorf("authkit: AuthorizationServer.GroupClients.Scopes[%d]: scope %q is declared twice", i, sc.Name)
		}
		scopes = append(scopes, sc)
	}
	if len(scopes) == 0 {
		scopes = nil
	}
	g.Scopes = scopes
	g.Agreements = dedup(g.Agreements)
	for _, key := range g.Agreements {
		if !slices.ContainsFunc(agreements, func(a AgreementConfig) bool { return a.Key == key }) {
			return fmt.Errorf("authkit: AuthorizationServer.GroupClients names agreement %q, which Agreements does not declare", key)
		}
	}
	return nil
}

func normalizeOAuthClient(cl *OAuthClientConfig, resources []ResourceServerConfig) error {
	cl.ID = strings.TrimSpace(cl.ID)
	if !clientIDPattern.MatchString(cl.ID) {
		return fmt.Errorf("invalid client ID %q (want 1-128 of letters, digits, '.', '_', '-', ':')", cl.ID)
	}
	if uuidPattern.MatchString(cl.ID) {
		return fmt.Errorf("client ID %q looks like a user ID", cl.ID)
	}
	cl.Name = strings.TrimSpace(cl.Name)
	if cl.Name == "" {
		cl.Name = cl.ID
	}
	cl.SecretSHA256 = strings.ToLower(strings.TrimSpace(cl.SecretSHA256))
	if cl.SecretSHA256 != "" {
		if b, err := hex.DecodeString(cl.SecretSHA256); err != nil || len(b) != 32 {
			return fmt.Errorf("client %q: SecretSHA256 must be the 64-character hex SHA-256 of the secret", cl.ID)
		}
	}
	var err error
	if cl.RedirectURIs, err = normalizeClientURIs(cl.RedirectURIs); err != nil {
		return fmt.Errorf("client %q: RedirectURIs: %w", cl.ID, err)
	}
	if cl.PostLogoutRedirectURIs, err = normalizeClientURIs(cl.PostLogoutRedirectURIs); err != nil {
		return fmt.Errorf("client %q: PostLogoutRedirectURIs: %w", cl.ID, err)
	}
	if len(cl.GrantTypes) == 0 {
		cl.GrantTypes = []OAuthGrantType{GrantAuthorizationCode}
	}
	grants := make([]OAuthGrantType, 0, len(cl.GrantTypes))
	for _, g := range cl.GrantTypes {
		switch g {
		case GrantAuthorizationCode, GrantRefreshToken, GrantTokenExchange, GrantClientCredentials, GrantJWTBearer:
		default:
			return fmt.Errorf("client %q: unsupported grant type %q", cl.ID, g)
		}
		if !slices.Contains(grants, g) {
			grants = append(grants, g)
		}
	}
	cl.GrantTypes = grants
	cl.Resources = dedup(cl.Resources)
	for _, id := range cl.Resources {
		if !slices.ContainsFunc(resources, func(r ResourceServerConfig) bool { return r.ID == id }) {
			return fmt.Errorf("client %q: resource %q is not in AuthorizationServer.Resources", cl.ID, id)
		}
	}
	if cl.Permissions, err = normalizeResourcePermissions(cl.Permissions); err != nil {
		return fmt.Errorf("client %q: Permissions: %w", cl.ID, err)
	}
	if cl.Origins, err = normalizeOrigins(cl.Origins); err != nil {
		return fmt.Errorf("client %q: Origins: %w", cl.ID, err)
	}
	cl.AuthorizationDetailsTypes = dedup(cl.AuthorizationDetailsTypes)
	for _, typ := range cl.AuthorizationDetailsTypes {
		if !scopePattern.MatchString(typ) {
			return fmt.Errorf("client %q: invalid authorization_details type %q", cl.ID, typ)
		}
	}
	switch {
	case OAuthClientAllows(*cl, GrantAuthorizationCode) && len(cl.RedirectURIs) == 0:
		return fmt.Errorf("client %q: the authorization_code grant needs RedirectURIs", cl.ID)
	case OAuthClientAllows(*cl, GrantRefreshToken) && !OAuthClientAllows(*cl, GrantAuthorizationCode):
		return fmt.Errorf("client %q: refresh tokens come only with the authorization_code grant", cl.ID)
	case OAuthClientAllows(*cl, GrantTokenExchange) && len(cl.Resources) == 0:
		return fmt.Errorf("client %q: token exchange needs Resources to mint for", cl.ID)
	case OAuthClientAllows(*cl, GrantClientCredentials) && !OAuthClientConfidential(*cl):
		return fmt.Errorf("client %q: client credentials need a confidential client (SecretSHA256)", cl.ID)
	case OAuthClientAllows(*cl, GrantClientCredentials) && len(cl.Resources) == 0:
		return fmt.Errorf("client %q: client credentials need Resources to mint for", cl.ID)
	case OAuthClientAllows(*cl, GrantJWTBearer) && len(cl.Resources) == 0:
		return fmt.Errorf("client %q: the jwt-bearer grant needs Resources to mint for", cl.ID)
	case OAuthClientAllows(*cl, GrantJWTBearer) && len(cl.AuthorizationDetailsTypes) == 0:
		return fmt.Errorf("client %q: the jwt-bearer grant needs AuthorizationDetailsTypes: its capabilities' operations", cl.ID)
	case len(cl.AuthorizationDetailsTypes) > 0 && !OAuthClientAllows(*cl, GrantJWTBearer):
		return fmt.Errorf("client %q: AuthorizationDetailsTypes are a jwt-bearer client's capability operations", cl.ID)
	case len(cl.Permissions) > 0 && !OAuthClientAllows(*cl, GrantClientCredentials):
		return fmt.Errorf("client %q: Permissions are a client-credentials client's own grants", cl.ID)
	}
	return nil
}

// normalizeOrigins trims and dedups browser origins: scheme://host[:port]
// only, https or http on a loopback host.
func normalizeOrigins(origins []string) ([]string, error) {
	out := dedup(origins)
	for _, raw := range out {
		u, err := url.Parse(raw)
		switch {
		case err != nil || u.Host == "" || u.Scheme+"://"+u.Host != raw:
			return nil, fmt.Errorf("%q is not an origin (scheme://host[:port])", raw)
		case u.Scheme == "https":
		case u.Scheme == "http" && loopbackHost(u.Hostname()):
		default:
			return nil, fmt.Errorf("%q must use https (http only on a loopback host)", raw)
		}
	}
	return out, nil
}

// normalizeClientURIs trims and dedups redirect URIs and refuses any that is
// not an absolute https URL, or http on a loopback host, without a fragment
// or user info. Matching is exact, so they are kept verbatim otherwise.
func normalizeClientURIs(uris []string) ([]string, error) {
	out := dedup(uris)
	for _, raw := range out {
		u, err := url.Parse(raw)
		switch {
		case err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "":
			return nil, fmt.Errorf("%q is not an absolute URL", raw)
		case u.Fragment != "" || strings.Contains(raw, "#"):
			return nil, fmt.Errorf("%q has a fragment", raw)
		case u.User != nil:
			return nil, fmt.Errorf("%q has user info", raw)
		case strings.Contains(raw, "*"):
			return nil, fmt.Errorf("%q has a wildcard; redirect URIs match exactly", raw)
		case u.Scheme == "https":
		case u.Scheme == "http" && loopbackHost(u.Hostname()):
		default:
			return nil, fmt.Errorf("%q must use https (http only on a loopback host)", raw)
		}
	}
	return out, nil
}

func validResourceID(id string) error {
	u, err := url.Parse(id)
	switch {
	case id == "" || err != nil || !u.IsAbs() || u.Opaque != "":
		return fmt.Errorf("resource ID %q must be an absolute URI", id)
	case u.Fragment != "" || strings.Contains(id, "#"):
		return fmt.Errorf("resource ID %q must not have a fragment", id)
	}
	return nil
}

func normalizeScopes(scopes []string) ([]string, error) {
	out := dedup(scopes)
	for _, s := range out {
		switch {
		case !scopePattern.MatchString(s):
			return nil, fmt.Errorf("invalid scope %q", s)
		case OIDCScope(s):
			return nil, fmt.Errorf("scope %q is defined by AuthKit", s)
		}
	}
	return out, nil
}

// normalizeResourcePermissions dedups a resource's permission ceiling and
// refuses anything but grant patterns outside the root namespace.
func normalizeResourcePermissions(perms []string) ([]string, error) {
	out := dedup(perms)
	for _, p := range out {
		if err := ident.ValidateGrantPattern(p); err != nil {
			return nil, err
		}
		if ident.Perm(p).Persona() == iam.RootPersona() {
			return nil, fmt.Errorf("permission %q is AuthKit's own root namespace", p)
		}
	}
	return out, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NormalizeClientURIs is the redirect URI rule for a client registered at
// run time: absolute https (http only on loopback), exact, no fragment.
func NormalizeClientURIs(uris []string) ([]string, error) { return normalizeClientURIs(uris) }
