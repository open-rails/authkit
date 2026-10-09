package engine

// The authorization server's other grants (#432): rotating refresh token
// families, RFC 8693 token exchange and client credentials, and RFC 7009
// revocation.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/secret"
)

const keyOAuthRefresh = "oauth:refresh:" // +hash of the family id

// oauthRefreshFamily is one chain of rotating refresh tokens. A token is
// <family>.<generation>.<secret>; the family holds only the current
// generation and its secret's hash. Presenting an older generation is
// reuse: the family is revoked, cutting off whoever holds the newer token.
type oauthRefreshFamily struct {
	ClientID  string `json:"client_id"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	// DeviceKeyID is a device-key sign-in's key, in place of SessionID.
	DeviceKeyID string    `json:"device_key_id,omitempty"`
	Scopes      []string  `json:"scopes"`
	Resource    string    `json:"resource,omitempty"`
	JKT         string    `json:"jkt,omitempty"`
	Generation  uint64    `json:"generation"`
	SecretHash  string    `json:"secret_hash"`
	ExpiresAt   time.Time `json:"expires_at"`
	// GrantID is the consented grant (RevokeOAuthGrant), CreatedAt its
	// start. An Offline family outlives its sign-in and ends when the
	// account's credentials change. One without a session (offline, or a
	// device key's) keeps the consent's assurance.
	GrantID              string          `json:"grant_id"`
	CreatedAt            time.Time       `json:"created_at"`
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
	Offline              bool            `json:"offline,omitempty"`
	CredentialVersion    int64           `json:"credential_version,omitempty"`
	AuthTime             int64           `json:"auth_time,omitempty"`
	AMR                  []string        `json:"amr,omitempty"`
	ACR                  string          `json:"acr,omitempty"`
}

// startOAuthRefreshFamily opens a family for m's grant and returns its first
// refresh token. A family with a DPoP key is bound to it. The family lives
// the client's refresh lifetime, capped by the grant decision.
func (s *Engine) startOAuthRefreshFamily(ctx context.Context, m oauthMint, credentialVersion int64) (string, error) {
	id := secret.Token(16)
	now := s.nowTime().UTC()
	f := oauthRefreshFamily{
		ClientID: m.client.ID, UserID: m.userID, SessionID: m.sessionID, DeviceKeyID: m.deviceKeyID, Scopes: m.scopes, Resource: m.resource,
		JKT: m.jkt, GrantID: m.grantID, CreatedAt: now, Offline: m.offline,
		ExpiresAt: grantExpiry(now, now.Add(config.OAuthClientRefreshTTL(s.cfg.AuthorizationServer, m.client)), m.decision),
	}
	if m.decision != nil {
		f.AuthorizationDetails = m.decision.AuthorizationDetails
	}
	if m.offline {
		f.CredentialVersion = credentialVersion
	}
	if m.offline || m.sessionID == "" {
		f.AuthTime, f.AMR, f.ACR = m.authTime, m.amr, m.acr
	}
	token := f.rotate(id)
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	key := keyOAuthRefresh + secret.Hash(id)
	ttl := time.Until(f.ExpiresAt)
	ok, err := s.ephemeral.Swap(ctx, key, nil, raw, ttl)
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "", errors.New("authkit: oauth: refresh family id collision")
	}
	if f.GrantID == "" {
		return token, nil
	}
	if err := s.ephemSetJSON(ctx, keyOAuthGrant+f.GrantID, key, ttl); err != nil {
		_ = s.ephemeral.Del(ctx, key)
		return "", err
	}
	return token, nil
}

// endOAuthFamily deletes a family and its grant index.
func (s *Engine) endOAuthFamily(ctx context.Context, key string, f oauthRefreshFamily) error {
	if err := s.ephemeral.Del(ctx, key); err != nil {
		return err
	}
	if f.GrantID == "" {
		return nil
	}
	return s.ephemeral.Del(ctx, keyOAuthGrant+f.GrantID)
}

// rotate advances f to a fresh generation and returns its token.
func (f *oauthRefreshFamily) rotate(id string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	value := base64.RawURLEncoding.EncodeToString(b)
	f.Generation++
	f.SecretHash = secret.Hash(value)
	return id + "." + strconv.FormatUint(f.Generation, 10) + "." + value
}

// parseRefreshToken splits a refresh token; ok is false for any other shape.
func parseRefreshToken(token string) (id string, generation uint64, value string, ok bool) {
	parts := strings.Split(token, ".")
	if len(token) > 256 || len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return "", 0, "", false
	}
	n, err := strconv.ParseUint(parts[1], 10, 64)
	return parts[0], n, parts[2], err == nil && n > 0
}

// RefreshOAuthTokens redeems a refresh token (RFC 6749 §6) once: it rotates
// the family and mints fresh tokens with live permissions while the sign-in
// (an offline grant: the account and its credentials) stands and the grant
// authorizer agrees. A replayed token revokes the family.
func (s *Engine) RefreshOAuthTokens(ctx context.Context, in authflow.OAuthRefresh) (authflow.OAuthTokens, error) {
	invalid := authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the refresh token is invalid, expired or revoked")
	id, generation, value, ok := parseRefreshToken(in.RefreshToken)
	if !ok {
		return authflow.OAuthTokens{}, invalid
	}
	key := keyOAuthRefresh + secret.Hash(id)
	var f oauthRefreshFamily
	raw, found, err := s.ephemReadJSON(ctx, key, &f)
	switch {
	case err != nil:
		return authflow.OAuthTokens{}, err
	case !found, !secret.Equal(f.ClientID, in.ClientID):
		return authflow.OAuthTokens{}, invalid
	case generation < f.Generation:
		return authflow.OAuthTokens{}, s.revokeReusedFamily(ctx, key, f)
	case generation > f.Generation || !secret.Equal(secret.Hash(value), f.SecretHash):
		return authflow.OAuthTokens{}, invalid
	case f.JKT != "" && !secret.Equal(f.JKT, in.JKT):
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "the refresh token is bound to another DPoP key")
	case in.Resource != "" && in.Resource != f.Resource:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "resource does not match the refresh token's")
	}
	scopes := f.Scopes
	if in.Scopes != nil {
		for _, scope := range in.Scopes {
			if !slices.Contains(f.Scopes, scope) {
				return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidScope, "scope "+strconv.Quote(scope)+" was not granted")
			}
		}
		scopes = in.Scopes
	}
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, f.ClientID)
	if !ok || !config.OAuthClientAllows(client, config.GrantRefreshToken) || f.Offline && !client.Offline {
		_ = s.endOAuthFamily(ctx, key, f)
		return authflow.OAuthTokens{}, invalid
	}
	if client.KeyBound && f.JKT == "" {
		_ = s.endOAuthFamily(ctx, key, f)
		return authflow.OAuthTokens{}, invalid
	}
	if len(f.AuthorizationDetails) > 0 {
		// The client no longer declares the grant's types.
		if _, oerr := authflow.ParseAuthorizationDetails(string(f.AuthorizationDetails), client.AuthorizationDetailsTypes); oerr != nil {
			_ = s.endOAuthFamily(ctx, key, f)
			return authflow.OAuthTokens{}, invalid
		}
	}
	if err := s.oauthFamilyStands(ctx, f); err != nil {
		_ = s.endOAuthFamily(ctx, key, f)
		return authflow.OAuthTokens{}, err
	}
	jkt := in.JKT
	if f.JKT != "" {
		jkt = f.JKT
	}
	decision, err := s.decideOAuthGrant(ctx, iam.OAuthGrantRequest{
		Kind: iam.OAuthGrantRefresh, GrantID: f.GrantID, ClientID: f.ClientID, UserID: f.UserID, SessionID: f.SessionID, DeviceKeyID: f.DeviceKeyID,
		Resource: f.Resource, Scopes: scopes, AuthorizationDetails: f.AuthorizationDetails, JWKThumbprint: jkt, Offline: f.Offline,
	}, client.AuthorizationDetailsTypes)
	if errors.Is(err, errOAuthGrantRefused) {
		_ = s.endOAuthFamily(ctx, key, f)
		s.oauthAudit(ctx, "oauth_grant_refused", f.UserID, map[string]string{"client_id": f.ClientID, "grant_id": f.GrantID})
	}
	if err != nil {
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	}
	next := f
	next.ExpiresAt = grantExpiry(f.CreatedAt, f.ExpiresAt, decision)
	if !s.nowTime().Before(next.ExpiresAt) {
		_ = s.endOAuthFamily(ctx, key, f)
		return authflow.OAuthTokens{}, invalid
	}
	token := next.rotate(id)
	updated, err := json.Marshal(next)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	swapped, err := s.ephemeral.Swap(ctx, key, raw, updated, time.Until(next.ExpiresAt))
	switch {
	case err != nil:
		return authflow.OAuthTokens{}, err
	case !swapped:
		// Another request redeemed this token first: the same token twice.
		return authflow.OAuthTokens{}, s.revokeReusedFamily(ctx, key, f)
	}
	authTime, amr, acr := f.AuthTime, f.AMR, f.ACR
	if !f.Offline && f.SessionID != "" {
		if authTime, amr, acr, err = s.sessionAssurance(ctx, f.UserID, f.SessionID); err != nil {
			return authflow.OAuthTokens{}, err
		}
	}
	tokens, err := s.mintOAuthTokens(ctx, oauthMint{
		client: client, userID: f.UserID, sessionID: f.SessionID, deviceKeyID: f.DeviceKeyID, scopes: scopes, resource: f.Resource,
		authTime: authTime, amr: amr, acr: acr, jkt: jkt,
		grantID: f.GrantID, offline: f.Offline, decision: decision, grantEnd: next.ExpiresAt,
	})
	if errors.Is(err, errOAuthGrantRefused) {
		_ = s.endOAuthFamily(ctx, key, next)
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	}
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	tokens.RefreshToken = token
	return tokens, nil
}

// oauthFamilyStands is whether f may still be redeemed: its sign-in stands,
// or for an offline grant its account is usable with unchanged credentials
// and its offline grants were not ended since (RevokeAccountSessions).
func (s *Engine) oauthFamilyStands(ctx context.Context, f oauthRefreshFamily) error {
	if !f.Offline {
		return s.oauthSignInStands(ctx, f.UserID, iam.SessionRef{SessionID: f.SessionID, DeviceKeyID: f.DeviceKeyID}, "the sign-in the refresh token was issued for has ended")
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	ended := authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the account the offline grant was issued for has changed its credentials or is unavailable")
	usable, _, err := userLive(ctx, s.pg, f.UserID, iam.SessionRef{})
	switch {
	case err != nil:
		return err
	case !usable:
		return ended
	}
	row, err := s.q.UserCredentialVersion(ctx, f.UserID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ended
	case err != nil:
		return err
	case row.CredentialVersion != f.CredentialVersion:
		return ended
	}
	var endedAt time.Time
	_, found, err := s.ephemReadJSON(ctx, keyOAuthOfflineEnded+f.UserID, &endedAt)
	switch {
	case err != nil:
		return err
	case found && !f.CreatedAt.After(endedAt):
		return ended
	}
	return nil
}

func (s *Engine) revokeReusedFamily(ctx context.Context, key string, f oauthRefreshFamily) error {
	if err := s.endOAuthFamily(ctx, key, f); err != nil {
		return err
	}
	s.oauthAudit(ctx, "oauth_refresh_reuse_revoked", f.UserID, map[string]string{"client_id": f.ClientID, "session_id": f.SessionID})
	return authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the refresh token was already used; its family is revoked")
}

// RevokeOAuthToken is RFC 7009 revocation for clientID: a refresh token
// ends its family. Anything else (an access token, which expires on its
// own, or an unknown token) is accepted and ignored, as the RFC requires.
func (s *Engine) RevokeOAuthToken(ctx context.Context, clientID, token string) error {
	id, _, _, ok := parseRefreshToken(token)
	if !ok {
		return nil
	}
	key := keyOAuthRefresh + secret.Hash(id)
	var f oauthRefreshFamily
	_, found, err := s.ephemReadJSON(ctx, key, &f)
	if err != nil || !found || !secret.Equal(f.ClientID, clientID) {
		return err
	}
	if err := s.endOAuthFamily(ctx, key, f); err != nil {
		return err
	}
	s.oauthAudit(ctx, "oauth_refresh_revoked", f.UserID, map[string]string{"client_id": f.ClientID, "session_id": f.SessionID})
	return nil
}

// ExchangeOAuthToken is RFC 8693 token exchange: the user's own AuthKit
// access token (a sign-in of this deployment) for an access token to one of
// the client's resources, standing on the same sign-in.
func (s *Engine) ExchangeOAuthToken(ctx context.Context, in authflow.OAuthTokenExchange) (authflow.OAuthTokens, error) {
	switch {
	case in.SubjectToken == "":
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "subject_token is required")
	case in.SubjectTokenType != authflow.TokenTypeAccessToken:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "subject_token_type must be "+authflow.TokenTypeAccessToken)
	case in.RequestedTokenType != "" && in.RequestedTokenType != authflow.TokenTypeAccessToken && in.RequestedTokenType != authflow.TokenTypeJWT:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "requested_token_type must be an access token")
	case len(in.SubjectToken) > 32<<10:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "subject_token is not a valid access token")
	}
	client, resource, err := s.oauthClientResource(in.ClientID, in.Resource)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	cl, err := s.auth.Verify(ctx, in.SubjectToken)
	signIn := iam.SessionRef{SessionID: cl.SessionID, DeviceKeyID: cl.DeviceKeyID}
	if err != nil || cl.Kind != iam.ActorUser || cl.UserID == "" || signIn.IsZero() || !strings.EqualFold(cl.JOSEType, jose.AccessTokenType) {
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "subject_token is not a valid access token for a sign-in here")
	}
	scopes, oerr := grantScopes(in.Scopes, resource, "email", "profile")
	if oerr != nil {
		return authflow.OAuthTokens{}, oerr
	}
	if err := s.oauthSignInStands(ctx, cl.UserID, signIn, "the subject token's sign-in has ended"); err != nil {
		return authflow.OAuthTokens{}, err
	}
	// A device-key sign-in's assurance is its token's.
	authTime, amr, acr := int64(0), cl.AMR, cl.ACR
	if !cl.AuthTime.IsZero() {
		authTime = cl.AuthTime.Unix()
	}
	if signIn.SessionID != "" {
		if authTime, amr, acr, err = s.sessionAssurance(ctx, cl.UserID, cl.SessionID); err != nil {
			return authflow.OAuthTokens{}, err
		}
	}
	details, oerr := authflow.ParseAuthorizationDetails(string(in.AuthorizationDetails), client.AuthorizationDetailsTypes)
	if oerr != nil {
		return authflow.OAuthTokens{}, oerr
	}
	decision, err := s.decideOAuthGrant(ctx, iam.OAuthGrantRequest{
		Kind: iam.OAuthGrantTokenExchange, ClientID: client.ID, UserID: cl.UserID, SessionID: cl.SessionID, DeviceKeyID: cl.DeviceKeyID,
		Resource: resource.ID, Scopes: scopes, AuthorizationDetails: details, JWKThumbprint: in.JKT,
	}, client.AuthorizationDetailsTypes)
	if err != nil {
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	}
	m := oauthMint{
		client: client, userID: cl.UserID, sessionID: cl.SessionID, deviceKeyID: cl.DeviceKeyID, scopes: scopes, resource: resource.ID,
		authTime: authTime, amr: amr, acr: acr, jkt: in.JKT, decision: decision, actor: client.ID,
	}
	tokens, err := s.mintOAuthTokens(ctx, m)
	if errors.Is(err, errOAuthGrantRefused) {
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	}
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	tokens.IssuedTokenType = authflow.TokenTypeAccessToken
	s.oauthAudit(ctx, "oauth_token_exchanged", cl.UserID, map[string]string{"client_id": client.ID, "session_id": cl.SessionID, "device_key_id": cl.DeviceKeyID, "resource": resource.ID})
	return tokens, nil
}

// OAuthClientCredentials mints a client's own access token: sub is its
// client_id and its permissions are its grants within the resource's
// ceiling.
func (s *Engine) OAuthClientCredentials(ctx context.Context, in authflow.OAuthClientCredentials) (authflow.OAuthTokens, error) {
	client, resource, err := s.oauthClientResource(in.ClientID, in.Resource)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	scopes, oerr := grantScopes(in.Scopes, resource)
	if oerr != nil {
		return authflow.OAuthTokens{}, oerr
	}
	details, oerr := authflow.ParseAuthorizationDetails(string(in.AuthorizationDetails), client.AuthorizationDetailsTypes)
	if oerr != nil {
		return authflow.OAuthTokens{}, oerr
	}
	decision, err := s.decideOAuthGrant(ctx, iam.OAuthGrantRequest{
		Kind: iam.OAuthGrantClientCredentials, ClientID: client.ID, Resource: resource.ID, Scopes: scopes,
		AuthorizationDetails: details, JWKThumbprint: in.JKT,
	}, client.AuthorizationDetailsTypes)
	if err != nil {
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthUnauthorizedClient)
	}
	m := oauthMint{client: client, scopes: scopes, resource: resource.ID, jkt: in.JKT, decision: decision}
	tokens, err := s.mintOAuthTokens(ctx, m)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	s.oauthAudit(ctx, "oauth_client_credentials", "", map[string]string{"client_id": client.ID, "resource": resource.ID})
	return tokens, nil
}

// oauthClientResource is the client and the resource it asks for: one of
// its Resources, or its only one when it names none.
func (s *Engine) oauthClientResource(clientID, resourceID string) (config.OAuthClientConfig, config.ResourceServerConfig, error) {
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, clientID)
	if !ok {
		return client, config.ResourceServerConfig{}, &authflow.OAuthError{Code: authflow.OAuthInvalidClient, Description: "unknown client", Status: 401}
	}
	if resourceID == "" && len(client.Resources) == 1 {
		resourceID = client.Resources[0]
	}
	resource, ok := config.FindResourceServer(s.cfg.AuthorizationServer, resourceID)
	if !ok || !slices.Contains(client.Resources, resourceID) {
		return client, resource, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "the client may not request tokens for that resource")
	}
	return client, resource, nil
}

// grantScopes checks requested scopes against the resource's (and extra
// AuthKit scopes allowed for the grant).
func grantScopes(requested []string, resource config.ResourceServerConfig, extra ...string) ([]string, *authflow.OAuthError) {
	granted := []string{}
	for _, scope := range requested {
		switch {
		case slices.Contains(granted, scope):
		case slices.Contains(resource.Scopes, scope), slices.Contains(extra, scope):
			granted = append(granted, scope)
		default:
			return nil, authflow.NewOAuthError(authflow.OAuthInvalidScope, "scope "+strconv.Quote(scope)+" is not available for this grant")
		}
	}
	return granted, nil
}
