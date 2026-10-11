package engine

// Group OAuth clients (#450): OAuth clients a group of a persona with
// OAuthClients registers at run time, by RFC 7591's metadata, managed under
// CAP <p>:credentials:manage (no open registration endpoint). They are
// third-party: each user consents to the scopes one asks for, it gets only
// verified contact claims, and its tokens act only in its group. A disabled
// or deleted client, or one of a deleted group, is refused at its next use.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/helpers/auth"
)

// standardScopes are the OpenID scopes a group client may ask for.
var standardScopes = []string{"openid", "email", "phone", "profile"}

const groupClientIDAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

func newGroupClientID() string {
	return config.GroupClientIDPrefix + secret.Code(26, groupClientIDAlphabet)
}

func invalidClient(param string, err error) error {
	return errmodel.E(errmodel.CodeInvalidOAuthClient, errmodel.WithParam(param), errmodel.WithCause(err))
}

// clientMetadata is a client's validated metadata.
type clientMetadata struct {
	name, logo, site, policy, tos string
	redirects, logoutRedirects    []string
	method                        iam.OAuthClientAuthMethod
	jwksURI                       string
	scopes                        []string
	backchannel                   string
}

func (m clientMetadata) params(clientID, groupID string, secretHash *string) db.GroupOAuthClientInsertParams {
	return db.GroupOAuthClientInsertParams{
		ClientID: clientID, GroupID: groupID, ClientName: m.name,
		LogoUri: nullable(m.logo), ClientUri: nullable(m.site), PolicyUri: nullable(m.policy), TosUri: nullable(m.tos),
		RedirectUris: m.redirects, PostLogoutRedirectUris: m.logoutRedirects,
		TokenEndpointAuthMethod: string(m.method), SecretHash: secretHash, JwksUri: nullable(m.jwksURI),
		Scopes: m.scopes, BackchannelLogoutUri: nullable(m.backchannel),
	}
}

// httpsURI checks an optional metadata URI: absolute https without a
// fragment ("" passes).
func httpsURI(param, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || len(raw) > 2048 {
		return "", invalidClient(param, fmt.Errorf("%q must be an absolute https URL without a fragment", raw))
	}
	return raw, nil
}

// validate normalizes m by RFC 7591's rules and this deployment's scopes.
func (s *Engine) validateClient(m *clientMetadata) error {
	m.name = strings.TrimSpace(m.name)
	if n := len([]rune(m.name)); n < 1 || n > 128 {
		return invalidClient("client_name", errors.New("client_name must be 1-128 characters"))
	}
	var err error
	for _, f := range []struct {
		param string
		v     *string
	}{{"logo_uri", &m.logo}, {"client_uri", &m.site}, {"policy_uri", &m.policy}, {"tos_uri", &m.tos}} {
		if *f.v, err = httpsURI(f.param, *f.v); err != nil {
			return err
		}
	}
	// AuthKit calls it, so it follows the jwks_uri rule (http only with
	// Token.AllowPrivateNetworkJWKS, for development).
	if m.backchannel = strings.TrimSpace(m.backchannel); m.backchannel != "" {
		if err := validateJWKSURI(m.backchannel, s.cfg.Token.AllowPrivateNetworkJWKS); err != nil || strings.Contains(m.backchannel, "#") {
			if err == nil {
				err = errors.New("backchannel_logout_uri must not have a fragment")
			}
			return invalidClient("backchannel_logout_uri", err)
		}
	}
	if m.redirects, err = config.NormalizeClientURIs(m.redirects); err != nil || len(m.redirects) == 0 || len(m.redirects) > 10 {
		if err == nil {
			err = errors.New("1-10 redirect_uris are required")
		}
		return invalidClient("redirect_uris", err)
	}
	if m.logoutRedirects, err = config.NormalizeClientURIs(m.logoutRedirects); err != nil || len(m.logoutRedirects) > 10 {
		if err == nil {
			err = errors.New("at most 10 post_logout_redirect_uris")
		}
		return invalidClient("post_logout_redirect_uris", err)
	}
	if m.logoutRedirects == nil {
		m.logoutRedirects = []string{}
	}
	m.jwksURI = strings.TrimSpace(m.jwksURI)
	switch m.method {
	case iam.OAuthClientPrivateKeyJWT:
		if err := validateJWKSURI(m.jwksURI, s.cfg.Token.AllowPrivateNetworkJWKS); err != nil {
			return invalidClient("jwks_uri", err)
		}
	case iam.OAuthClientSecretBasic, iam.OAuthClientNone:
		if m.jwksURI != "" {
			return invalidClient("jwks_uri", errors.New("only private_key_jwt publishes a jwks_uri"))
		}
	default:
		return invalidClient("token_endpoint_auth_method", fmt.Errorf("token_endpoint_auth_method %q is not private_key_jwt, client_secret_basic or none", m.method))
	}
	scopes := []string{}
	for _, scope := range m.scopes {
		if slices.Contains(scopes, scope) {
			continue
		}
		if _, host := config.FindGroupClientScope(s.cfg.AuthorizationServer, scope); !host && !slices.Contains(standardScopes, scope) {
			return invalidClient("scope", fmt.Errorf("scope %q is not one a group client may request", scope))
		}
		scopes = append(scopes, scope)
	}
	if !slices.Contains(scopes, "openid") {
		return invalidClient("scope", errors.New("scope must include openid"))
	}
	slices.Sort(scopes)
	m.scopes = scopes
	return nil
}

// clientsManager is who's authority over g's clients: CAP
// <p>:credentials:manage in a persona with OAuthClients.
func (s *Engine) clientsManager(ctx context.Context, st *permissionGroupStore, who auth.Identity, g groupTarget) error {
	if p, ok := s.groupSchemaOrDefault().Persona(g.Persona); !ok || !p.OAuthClients {
		return fmt.Errorf("persona %q does not register OAuth clients: %w", g.Persona, iam.ErrInsufficientAuthority)
	}
	a, err := s.identityAuthority(ctx, st, who, g)
	if err != nil {
		return err
	}
	return a.requireCap(ident.CredentialsManage(g.Persona))
}

func clientEvent(kind iam.EventKind, g groupTarget, clientID string) iam.Event {
	e := groupEvent(kind, g.ID, g.Persona)
	e.ClientID = clientID
	return e
}

func publicClient(row db.GroupOauthClient) iam.OAuthClient {
	return iam.OAuthClient{
		ClientID: row.ClientID, GroupID: row.PermissionGroupID, ClientName: row.ClientName,
		LogoURI: row.LogoUri, ClientURI: row.ClientUri, PolicyURI: row.PolicyUri, TOSURI: row.TosUri,
		RedirectURIs: row.RedirectUris, PostLogoutRedirectURIs: row.PostLogoutRedirectUris,
		TokenEndpointAuthMethod: iam.OAuthClientAuthMethod(row.TokenEndpointAuthMethod), JWKSURI: row.JwksUri,
		Scope: strings.Join(row.Scopes, " "), BackchannelLogoutURI: row.BackchannelLogoutUri,
		Disabled: row.DisabledAt != nil, DisabledAt: row.DisabledAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

// CreateGroupOAuthClient registers an OAuth client in ref under CAP
// <p>:credentials:manage. A client_secret_basic client's secret is returned
// this once; AuthKit keeps its hash.
func (s *Engine) CreateGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, n iam.NewOAuthClient, opts ...ops.Option) (iam.OAuthClientCreated, error) {
	host, err := hostTx("CreateGroupOAuthClient", opts)
	if err != nil {
		return iam.OAuthClientCreated{}, err
	}
	if err := requireIdentity(who); err != nil {
		return iam.OAuthClientCreated{}, err
	}
	m := clientMetadata{
		name: n.ClientName, logo: n.LogoURI, site: n.ClientURI, policy: n.PolicyURI, tos: n.TOSURI,
		redirects: n.RedirectURIs, logoutRedirects: n.PostLogoutRedirectURIs, method: n.TokenEndpointAuthMethod,
		jwksURI: n.JWKSURI, scopes: strings.Fields(n.Scope), backchannel: n.BackchannelLogoutURI,
	}
	if err := s.validateClient(&m); err != nil {
		return iam.OAuthClientCreated{}, err
	}
	var out iam.OAuthClientCreated
	err = s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := s.clientsManager(ctx, st, who, g); err != nil {
			return err
		}
		q := db.New(st.q)
		count, err := q.GroupOAuthClientCount(ctx, g.ID)
		if err != nil {
			return err
		}
		if count >= iam.MaxGroupOAuthClients {
			return iam.ErrOAuthClientLimitReached
		}
		var hash *string
		var plain string
		if m.method == iam.OAuthClientSecretBasic {
			plain = secret.Token(32)
			h := secret.Hash(plain)
			hash = &h
		}
		row, err := q.GroupOAuthClientInsert(ctx, m.params(newGroupClientID(), g.ID, hash))
		if err != nil {
			return err
		}
		out = iam.OAuthClientCreated{OAuthClient: publicClient(row)}
		if plain != "" {
			out.ClientSecret = &plain
		}
		return st.record(ctx, clientEvent(iam.EventOAuthClientCreated, g, row.ClientID))
	})
	return out, err
}

// GroupOAuthClients returns ref's clients, oldest first.
func (s *Engine) GroupOAuthClients(ctx context.Context, ref iam.GroupRef) ([]iam.OAuthClient, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.GroupOAuthClientsByGroup(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	out := make([]iam.OAuthClient, 0, len(rows))
	for _, r := range rows {
		out = append(out, publicClient(r))
	}
	return out, nil
}

// GroupOAuthClient returns one of ref's clients.
func (s *Engine) GroupOAuthClient(ctx context.Context, ref iam.GroupRef, clientID string) (iam.OAuthClient, error) {
	if err := s.requirePG(); err != nil {
		return iam.OAuthClient{}, err
	}
	g, err := s.resolveGroup(ctx, s.groupStore(), ref)
	if err != nil {
		return iam.OAuthClient{}, err
	}
	row, err := s.q.GroupOAuthClientInGroup(ctx, db.GroupOAuthClientInGroupParams{ClientID: clientID, GroupID: g.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.OAuthClient{}, iam.ErrOAuthClientNotFound
	}
	if err != nil {
		return iam.OAuthClient{}, err
	}
	return publicClient(row), nil
}

// UpdateGroupOAuthClient changes a client of ref under CAP
// <p>:credentials:manage. Disabling it refuses its sign-ins and every token
// it holds at its next use.
func (s *Engine) UpdateGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, clientID string, u iam.OAuthClientUpdate, opts ...ops.Option) (iam.OAuthClient, error) {
	host, err := hostTx("UpdateGroupOAuthClient", opts)
	if err != nil {
		return iam.OAuthClient{}, err
	}
	if err := requireIdentity(who); err != nil {
		return iam.OAuthClient{}, err
	}
	var out iam.OAuthClient
	err = s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := s.clientsManager(ctx, st, who, g); err != nil {
			return err
		}
		q := db.New(st.q)
		row, err := q.GroupOAuthClientInGroup(ctx, db.GroupOAuthClientInGroupParams{ClientID: clientID, GroupID: g.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrOAuthClientNotFound
		}
		if err != nil {
			return err
		}
		m := clientMetadata{
			name: row.ClientName, logo: deref(row.LogoUri), site: deref(row.ClientUri), policy: deref(row.PolicyUri), tos: deref(row.TosUri),
			redirects: row.RedirectUris, logoutRedirects: row.PostLogoutRedirectUris, method: iam.OAuthClientAuthMethod(row.TokenEndpointAuthMethod),
			jwksURI: deref(row.JwksUri), scopes: row.Scopes, backchannel: deref(row.BackchannelLogoutUri),
		}
		set := func(dst *string, v *string) {
			if v != nil {
				*dst = *v
			}
		}
		set(&m.name, u.ClientName)
		set(&m.logo, u.LogoURI)
		set(&m.site, u.ClientURI)
		set(&m.policy, u.PolicyURI)
		set(&m.tos, u.TOSURI)
		set(&m.jwksURI, u.JWKSURI)
		set(&m.backchannel, u.BackchannelLogoutURI)
		if u.RedirectURIs != nil {
			m.redirects = *u.RedirectURIs
		}
		if u.PostLogoutRedirectURIs != nil {
			m.logoutRedirects = *u.PostLogoutRedirectURIs
		}
		if u.Scope != nil {
			m.scopes = strings.Fields(*u.Scope)
		}
		if err := s.validateClient(&m); err != nil {
			return err
		}
		disabled := row.DisabledAt != nil
		if u.Disabled != nil {
			disabled = *u.Disabled
		}
		p := m.params(row.ClientID, g.ID, nil)
		updated, err := q.GroupOAuthClientUpdate(ctx, db.GroupOAuthClientUpdateParams{
			ClientID: row.ClientID, GroupID: g.ID, ClientName: p.ClientName, LogoUri: p.LogoUri, ClientUri: p.ClientUri,
			PolicyUri: p.PolicyUri, TosUri: p.TosUri, RedirectUris: p.RedirectUris, PostLogoutRedirectUris: p.PostLogoutRedirectUris,
			JwksUri: p.JwksUri, Scopes: p.Scopes, BackchannelLogoutUri: p.BackchannelLogoutUri, Disabled: disabled,
		})
		if err != nil {
			return err
		}
		out = publicClient(updated)
		return st.record(ctx, clientEvent(iam.EventOAuthClientUpdated, g, row.ClientID))
	})
	return out, err
}

// RotateGroupOAuthClientSecret replaces a client_secret_basic client's
// secret, returning the new one this once; the old one stops at once.
func (s *Engine) RotateGroupOAuthClientSecret(ctx context.Context, who auth.Identity, ref iam.GroupRef, clientID string, opts ...ops.Option) (string, error) {
	host, err := hostTx("RotateGroupOAuthClientSecret", opts)
	if err != nil {
		return "", err
	}
	if err := requireIdentity(who); err != nil {
		return "", err
	}
	plain := secret.Token(32)
	err = s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := s.clientsManager(ctx, st, who, g); err != nil {
			return err
		}
		n, err := db.New(st.q).GroupOAuthClientSetSecret(ctx, db.GroupOAuthClientSetSecretParams{ClientID: clientID, GroupID: g.ID, SecretHash: nullable(secret.Hash(plain))})
		if err != nil {
			return err
		}
		if n == 0 {
			return iam.ErrOAuthClientNotFound
		}
		return st.record(ctx, clientEvent(iam.EventOAuthClientUpdated, g, clientID))
	})
	if err != nil {
		return "", err
	}
	return plain, nil
}

// DeleteGroupOAuthClient deletes a client of ref and every consent to it:
// its tokens are refused at their next use.
func (s *Engine) DeleteGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, clientID string, opts ...ops.Option) error {
	host, err := hostTx("DeleteGroupOAuthClient", opts)
	if err != nil {
		return err
	}
	if err := requireIdentity(who); err != nil {
		return err
	}
	return s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := s.clientsManager(ctx, st, who, g); err != nil {
			return err
		}
		n, err := db.New(st.q).GroupOAuthClientDelete(ctx, db.GroupOAuthClientDeleteParams{ClientID: clientID, GroupID: g.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			return iam.ErrOAuthClientNotFound
		}
		return st.record(ctx, clientEvent(iam.EventOAuthClientDeleted, g, clientID))
	})
}

// OAuthClient resolves clientID for the authorization and resource servers:
// a declared client, else a live group client. ok is false for neither.
func (s *Engine) OAuthClient(ctx context.Context, clientID string) (authflow.OAuthClient, bool, error) {
	if c, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, clientID); ok {
		return authflow.OAuthClient{OAuthClientConfig: c}, true, nil
	}
	if !config.GroupClientsEnabled(s.cfg.AuthorizationServer) || !strings.HasPrefix(clientID, config.GroupClientIDPrefix) || s.pg == nil {
		return authflow.OAuthClient{}, false, nil
	}
	row, err := s.q.GroupOAuthClientLive(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authflow.OAuthClient{}, false, nil
	}
	if err != nil {
		return authflow.OAuthClient{}, false, err
	}
	return s.groupClient(row), true, nil
}

// groupClient is row as the authorization server sees it: the code and
// refresh grants, for the resources its scopes name.
func (s *Engine) groupClient(row db.GroupOauthClient) authflow.OAuthClient {
	c := config.OAuthClientConfig{
		ID: row.ClientID, Name: row.ClientName, RedirectURIs: row.RedirectUris, PostLogoutRedirectURIs: row.PostLogoutRedirectUris,
		GrantTypes: []config.OAuthGrantType{config.GrantAuthorizationCode, config.GrantRefreshToken},
		Agreements: s.cfg.AuthorizationServer.GroupClients.Agreements,
	}
	if row.SecretHash != nil {
		c.SecretSHA256 = *row.SecretHash
	}
	for _, scope := range row.Scopes {
		if sc, ok := config.FindGroupClientScope(s.cfg.AuthorizationServer, scope); ok && !slices.Contains(c.Resources, sc.Resource) {
			c.Resources = append(c.Resources, sc.Resource)
		}
	}
	return authflow.OAuthClient{OAuthClientConfig: c, Group: &authflow.GroupClient{
		GroupID: row.PermissionGroupID, AuthMethod: iam.OAuthClientAuthMethod(row.TokenEndpointAuthMethod), JWKSURI: deref(row.JwksUri),
		Scopes: row.Scopes, BackchannelLogoutURI: deref(row.BackchannelLogoutUri), LogoURI: deref(row.LogoUri), ClientURI: deref(row.ClientUri),
		PolicyURI: deref(row.PolicyUri), TOSURI: deref(row.TosUri), UpdatedAt: row.UpdatedAt,
	}}
}

// OAuthClientOrigin reports whether a live group client redirects to
// origin, so a browser client there may call the token endpoint.
func (s *Engine) OAuthClientOrigin(ctx context.Context, origin string) (bool, error) {
	if !config.GroupClientsEnabled(s.cfg.AuthorizationServer) || s.pg == nil {
		return false, nil
	}
	return s.q.GroupOAuthClientRedirectOrigin(ctx, origin)
}
