package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

func personalTokenRoles() *config.Roles {
	r := config.NewRoles()
	org := r.Persona("org", config.APIKeys)
	read, write := org.Permission("posts", "read"), org.Permission("posts", "write")
	secret := org.Permission("secrets", "read")
	org.RequireMFA(secret)
	org.Role("reader", read)
	org.Role("writer", read, write)
	org.Role("manager", org.Credentials.Manage, org.Members.Manage, read, write)
	return r
}

func personalSession(t *testing.T, e *Engine, id string) auth.Identity {
	t.Helper()
	session, _, err := e.issueRefreshSession(t.Context(), id)
	require.NoError(t, err)
	return iam.InSession(iam.UserIdentity(id), iam.SessionRef{SessionID: session})
}

func TestPersonalTokensStayWithinLiveOwnerAuthority(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://personal-a.test", "https://personal-b.test"}
	apps := make([]*Engine, 2)
	for i, schema := range []string{"personal_a_jobs", "personal_b_jobs"} {
		cfg := credentialConfig(personalTokenRoles())
		cfg.PersonalAccessTokens.Enabled = true
		cfg.Token.Issuer, cfg.Token.AccountIssuers = issuers[i], issuers
		cfg.Database.RiverSchema = schema
		var err error
		apps[i], err = New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
		require.NoError(t, err)
		t.Cleanup(func() { _ = apps[i].Close(context.Background()) })
	}
	a, b := apps[0], apps[1]
	user := newUser(t, a, "personal")
	other := newUser(t, a, "personalother")
	gid, err := seedGroup(t.Context(), a, ident.Persona("org"), other.ID)
	require.NoError(t, err)
	group := iam.GroupByID(gid)
	grantRole(t, a, group, iam.UserSubject(user.ID), "writer")
	session := personalSession(t, a, user.ID)
	read, write := ident.Perm("org:posts:read"), ident.Perm("org:posts:write")
	input := iam.NewPersonalAccessToken{Name: "my script", GroupID: gid, Permissions: []iam.Perm{read, write}}
	created, err := a.CreatePersonalAccessToken(t.Context(), session, input)
	require.NoError(t, err, "ordinary members need no organization credentials-management grant")
	require.Equal(t, user.ID, created.Token.OwnerUserID)
	require.True(t, created.Token.ExpiresAt.After(time.Now().Add(29*24*time.Hour)))
	_, err = b.ResolvePersonalAccessToken(t.Context(), created.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid)
	request := httptest.NewRequest(http.MethodGet, issuers[0]+"/posts", nil)
	request.Header.Set("Authorization", "Bearer "+created.Secret)
	verified, err := verify.AuthenticateRequest(t.Context(), a, request)
	require.NoError(t, err)
	require.Equal(t, user.ID, verified.Identity().Subject)
	require.Equal(t, auth.CredentialPersonalAccessToken, verified.Identity().Credential.Kind)
	encoded, err := json.Marshal(verified.Identity())
	require.NoError(t, err)
	var decoded auth.Identity
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, auth.CredentialPersonalAccessToken, decoded.Credential.Kind)
	_, sealed := iam.StateOf(decoded)
	require.False(t, sealed, "serialization never creates an authoritative credential")
	checker := verified.(auth.PermissionChecker)
	direct := verified.(auth.DirectPermissionChecker)
	scope := auth.Scope{Authority: issuers[0], ID: gid}
	for _, perm := range []iam.Perm{read, write} {
		ok, err := checker.Can(t.Context(), scope, perm.String())
		require.NoError(t, err)
		require.True(t, ok)
	}
	ok, err := direct.CanDirect(t.Context(), scope, read.String())
	require.NoError(t, err)
	require.True(t, ok)
	claims, err := a.Verify(t.Context(), created.Secret)
	require.NoError(t, err)
	require.False(t, claims.IsUser())
	require.Empty(t, claims.SessionID)
	require.Empty(t, claims.AMR)
	require.Zero(t, claims.AuthTime)
	require.Error(t, a.CheckRecentSignIn(t.Context(), claims))
	_, err = a.CreateAPIKey(t.Context(), iam.PersonalAccessTokenIdentity(created.Token.ID), group, iam.NewAPIKey{Name: "cannot delegate", Role: mustRole("org:reader")})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = a.CreatePersonalAccessToken(t.Context(), iam.PersonalAccessTokenIdentity(created.Token.ID), input)
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)

	grantRole(t, b, group, iam.UserSubject(user.ID), "reader")
	ok, err = checker.Can(t.Context(), scope, write.String())
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = checker.Can(t.Context(), scope, read.String())
	require.NoError(t, err)
	require.True(t, ok, "a partial role reduction keeps unaffected permissions")
	perms, err := a.EffectivePermissions(t.Context(), iam.PersonalAccessTokenIdentity(created.Token.ID), []iam.GroupRef{group})
	require.NoError(t, err)
	require.Equal(t, []iam.Perm{read}, perms[gid])
	resolved, err := a.ResolvePersonalAccessToken(t.Context(), created.Secret)
	require.NoError(t, err)
	require.Equal(t, []iam.Perm{read}, resolved.Permissions)
	otherSession := personalSession(t, a, other.ID)
	listed, err := a.ListPersonalAccessTokens(t.Context(), otherSession, iam.PageRequest{})
	require.NoError(t, err)
	require.Empty(t, listed.Items)
	require.NoError(t, a.RevokePersonalAccessToken(t.Context(), otherSession, created.Token.ID))
	_, err = a.ResolvePersonalAccessToken(t.Context(), created.Secret)
	require.NoError(t, err, "another user cannot revoke this token")
	listed, err = a.ListPersonalAccessTokens(t.Context(), session, iam.PageRequest{})
	require.NoError(t, err)
	raw, err := json.Marshal(listed)
	require.NoError(t, err)
	require.NotContains(t, string(raw), created.Secret)
	require.NotContains(t, string(raw), "secret_hash")
	require.NotContains(t, string(raw), "lookup_id")
	require.NoError(t, a.RevokePersonalAccessToken(t.Context(), session, created.Token.ID))
	ok, err = checker.Can(t.Context(), scope, read.String())
	require.NoError(t, err)
	require.False(t, ok, "a retained Verified cannot outlive revocation")
	_, err = a.ResolvePersonalAccessToken(t.Context(), created.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid)

	for _, forbidden := range []string{"org:*", "org:credentials:manage", "org:secrets:read", "missing:unknown:read"} {
		input.Permissions = []iam.Perm{ident.Perm(forbidden)}
		_, err = a.CreatePersonalAccessToken(t.Context(), session, input)
		require.Equal(t, errmodel.CodeInvalidRequest, errmodel.CodeOf(err), forbidden)
	}
	input.Permissions = []iam.Perm{read}
	fresh, err := a.CreatePersonalAccessToken(t.Context(), session, input)
	require.NoError(t, err)
	freshRequest := request.Clone(t.Context())
	freshRequest.Header.Set("Authorization", "Bearer "+fresh.Secret)
	freshVerified, err := verify.AuthenticateRequest(t.Context(), a, freshRequest)
	require.NoError(t, err)
	require.NoError(t, a.Ban(t.Context(), iam.SystemIdentity(), user.ID, iam.Ban{Reason: "disabled"}))
	_, err = a.ResolvePersonalAccessToken(t.Context(), fresh.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid)
	ok, err = freshVerified.(auth.PermissionChecker).Can(t.Context(), scope, read.String())
	require.NoError(t, err)
	require.False(t, ok, "a cached identity cannot bypass an account ban")
	require.NoError(t, a.Unban(t.Context(), iam.SystemIdentity(), user.ID))
	_, err = a.ResolvePersonalAccessToken(t.Context(), fresh.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid, "unbanning never revives personal credentials")
	session = personalSession(t, a, user.ID)
	state, _ := iam.StateOf(session)
	sref, _ := state.Session()
	_, err = a.pg.Exec(t.Context(), `UPDATE refresh_sessions SET last_authenticated_at=now()-interval '1 day' WHERE id=$1`, sref.SessionID)
	require.NoError(t, err)
	_, err = a.CreatePersonalAccessToken(t.Context(), session, input)
	require.Equal(t, errmodel.CodeStepUpRequired, errmodel.CodeOf(err))
	require.NoError(t, a.MarkSessionAuthenticated(t.Context(), user.ID, sref.SessionID))
	deleted, err := a.CreatePersonalAccessToken(t.Context(), session, input)
	require.NoError(t, err)
	deletedRequest := request.Clone(t.Context())
	deletedRequest.Header.Set("Authorization", "Bearer "+deleted.Secret)
	deletedVerified, err := verify.AuthenticateRequest(t.Context(), a, deletedRequest)
	require.NoError(t, err)
	require.NoError(t, itemErr(a.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})))
	require.NoError(t, itemErr(a.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})))
	_, err = a.ResolvePersonalAccessToken(t.Context(), deleted.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid, "restoring an account never revives personal credentials")
	ok, err = deletedVerified.(auth.PermissionChecker).Can(t.Context(), scope, read.String())
	require.NoError(t, err)
	require.False(t, ok)
	session = personalSession(t, a, user.ID)
	expired, err := a.CreatePersonalAccessToken(t.Context(), session, input)
	require.NoError(t, err)
	_, err = a.pg.Exec(t.Context(), `UPDATE personal_access_tokens SET expires_at=now()-interval '1 second' WHERE id=$1`, expired.Token.ID)
	require.NoError(t, err)
	_, err = a.ResolvePersonalAccessToken(t.Context(), expired.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid)
	require.NoError(t, itemErr(a.PurgeUsers(t.Context(), []string{user.ID})))
	require.NoError(t, a.deleteDueAccounts(t.Context()))
	require.NoError(t, b.deleteDueAccounts(t.Context()))
	var remaining int
	require.NoError(t, a.pg.QueryRow(t.Context(), `SELECT count(*) FROM personal_access_tokens WHERE owner_user_id=$1`, user.ID).Scan(&remaining))
	require.Zero(t, remaining, "hard deletion removes the user's personal tokens")
}

func TestOrganizationKeysSurviveCreatorDeparture(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	creator := f.user("orgcreator")
	grantRole(t, f.e, f.acme, creator, "manager")
	key, err := f.e.CreateAPIKey(ctx, iam.UserIdentity(creator.ID), f.acme, iam.NewAPIKey{Name: "organization integration", Role: f.role("member")})
	require.NoError(t, err)
	retired, err := f.e.CreateAPIKey(ctx, iam.UserIdentity(creator.ID), f.acme, iam.NewAPIKey{Name: "already revoked", Role: f.role("member")})
	require.NoError(t, err)
	require.NoError(t, f.e.RevokeAPIKey(ctx, iam.SystemIdentity(), f.acme, retired.APIKey.ID))
	check := func() {
		t.Helper()
		_, err := f.e.ResolveAPIKey(ctx, key.Secret)
		require.NoError(t, err)
		_, err = f.e.ResolveAPIKey(ctx, retired.Secret)
		require.ErrorIs(t, err, iam.ErrAPIKeyRevoked, "a policy change never revives revoked keys")
	}
	check()
	grantRole(t, f.e, f.acme, creator, "member")
	check()
	require.NoError(t, f.e.Ban(ctx, iam.SystemIdentity(), creator.ID, iam.Ban{Reason: "left"}))
	check()
	require.NoError(t, itemErr(f.e.PurgeUsers(ctx, []string{creator.ID})))
	require.NoError(t, f.e.deleteDueAccounts(ctx))
	var audit *string
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT created_by::text FROM api_keys WHERE id=$1`, key.APIKey.ID).Scan(&audit))
	require.Nil(t, audit)
	check()
	require.NoError(t, f.e.DeleteGroup(ctx, f.acme))
	_, err = f.e.ResolveAPIKey(ctx, key.Secret)
	require.ErrorIs(t, err, iam.ErrAPIKeyInvalid)
}

func TestPersonalTokenHTTPHasNoAccountOrCredentialPrivileges(t *testing.T) {
	cfg := testConfig()
	cfg.Roles = personalTokenRoles()
	cfg.TwoFactor.Mode = iam.TwoFactorOptional
	cfg.PersonalAccessTokens.Enabled = true
	f := newAccountFlow(t, testdb.ScratchPostgres(t).Pool, cfg, config.Deps{})
	u := newUser(t, f.engine, "personalhttp")
	gid, err := seedGroup(t.Context(), f.engine, ident.Persona("org"), "")
	require.NoError(t, err)
	grantRole(t, f.engine, iam.GroupByID(gid), iam.UserSubject(u.ID), "reader")
	login := f.expect(http.StatusOK, f.post("/password/login", map[string]string{"identifier": *u.Email, "password": testPassword})).tokens()
	res := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/personal-access-tokens", login.AccessToken,
		map[string]any{"name": "HTTP read", "group_id": gid, "permissions": []string{"org:posts:read"}}))
	var created iam.PersonalAccessTokenCreated
	require.NoError(t, json.Unmarshal([]byte(res.raw), &created))
	require.Equal(t, u.ID, created.Token.OwnerUserID)
	require.NotEmpty(t, created.Secret)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/me"}, {http.MethodPatch, "/me"},
		{http.MethodGet, "/me/security"}, {http.MethodGet, "/me/groups"},
		{http.MethodGet, "/me/permissions?group_id=" + gid},
		{http.MethodPut, "/me/password"}, {http.MethodPut, "/me/email"},
		{http.MethodGet, "/me/sessions"}, {http.MethodDelete, "/me/sessions"},
		{http.MethodPost, "/me/2fa/setup"}, {http.MethodDelete, "/me/2fa"},
		{http.MethodPost, "/me/2fa/backup-codes"}, {http.MethodDelete, "/me"},
		{http.MethodGet, "/me/personal-access-tokens"}, {http.MethodPost, "/me/personal-access-tokens"},
		{http.MethodDelete, "/me/personal-access-tokens/" + created.Token.ID},
	} {
		got := f.request(route.method, route.path, created.Secret, map[string]string{"username": "overwritten", "new_password": "Changed-password-1"})
		require.GreaterOrEqual(t, got.status, 400, "%s %s: %s", route.method, route.path, got.raw)
	}
	list := f.expect(http.StatusOK, f.request(http.MethodGet, "/me/personal-access-tokens", login.AccessToken, nil))
	require.NotContains(t, list.raw, created.Secret)
	require.NotContains(t, list.raw, "secret_hash")
	require.NotContains(t, list.raw, "lookup_id")
	current, err := f.engine.User(t.Context(), iam.UserByID(u.ID))
	require.NoError(t, err)
	require.Equal(t, *u.Username, current.Username)
	require.NoError(t, f.engine.CheckUserPassword(t.Context(), u.ID, testPassword))
	require.NoError(t, f.engine.RevokePersonalAccessToken(t.Context(), personalSession(t, f.engine, u.ID), created.Token.ID))
	_, err = f.engine.ResolvePersonalAccessToken(t.Context(), created.Secret)
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid)
}

func TestPersonalTokensAreDisabledByDefault(t *testing.T) {
	f := newAccountFlow(t, testdb.ScratchPostgres(t).Pool, testConfig(), config.Deps{})
	require.False(t, f.engine.cfg.PersonalAccessTokens.Enabled)
	f.expect(http.StatusNotFound, f.request(http.MethodGet, "/me/personal-access-tokens", "", nil))
	_, err := f.engine.ResolvePersonalAccessToken(t.Context(), "pat_notavalidtoken")
	require.ErrorIs(t, err, iam.ErrPersonalAccessTokenInvalid)
}
