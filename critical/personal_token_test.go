package critical_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func (f *fixture) personal(t *testing.T, permissions ...iam.Perm) (iam.PersonalAccessTokenCreated, iam.Group, auth.Identity) {
	t.Helper()
	group, _, who := f.ownedGroup(t)
	token, err := f.auth.CreatePersonalAccessToken(t.Context(), who, iam.NewPersonalAccessToken{Name: "critical personal token", GroupID: group.ID, Permissions: permissions})
	noError(t, err)
	return token, group, who
}

func TestCriticalPersonalTokens(t *testing.T) {
	t.Run("AK-J17-C01_create_list_use_revoke_and_expire", func(t *testing.T) {
		f := newFixture(t)
		token, group, who := f.personal(t, f.read)
		resolved, err := f.auth.ResolvePersonalAccessToken(t.Context(), token.Secret)
		noError(t, err)
		if resolved.OwnerUserID != who.Subject || resolved.Group.ID != group.ID || len(resolved.Permissions) != 1 || resolved.Permissions[0] != f.read {
			t.Fatal("personal token did not retain its explicit owner, group and ceiling")
		}
		page, err := f.auth.ListPersonalAccessTokens(t.Context(), who, iam.PageRequest{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].ID != token.Token.ID {
			t.Fatal("personal-token list lost its valid control")
		}
		noError(t, f.auth.RevokePersonalAccessToken(t.Context(), who, token.Token.ID))
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), token.Secret)
		if !errors.Is(err, iam.ErrPersonalAccessTokenInvalid) {
			t.Fatalf("revoked personal token still resolved: %v", err)
		}
		expired, err := f.auth.CreatePersonalAccessToken(t.Context(), who, iam.NewPersonalAccessToken{Name: "expiry control", GroupID: group.ID, Permissions: []iam.Perm{f.read}})
		noError(t, err)
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), expired.Secret)
		noError(t, err)
		// PostgreSQL owns PAT expiry. Change only this fixture's deadline,
		// then observe authority through the real public resolver.
		tag, err := f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "personal_access_tokens"}.Sanitize()+" SET expires_at=statement_timestamp()-interval '1 second' WHERE id=$1", expired.Token.ID)
		noError(t, err)
		if tag.RowsAffected() != 1 {
			t.Fatal("expiry fixture did not identify its issued token")
		}
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), expired.Secret)
		if !errors.Is(err, iam.ErrPersonalAccessTokenInvalid) {
			t.Fatalf("expired personal token still resolved: %v", err)
		}
	})
	t.Run("AK-J17-C02_wildcard_unknown_and_credential_permissions_are_refused", func(t *testing.T) {
		f := newFixture(t)
		group, _, who := f.ownedGroup(t)
		var unknown iam.Perm
		noError(t, unknown.UnmarshalText([]byte("shop:orders:unknown")))
		for _, permission := range []iam.Perm{f.shop.All(), unknown, f.shop.Credentials.Manage} {
			_, err := f.auth.CreatePersonalAccessToken(t.Context(), who, iam.NewPersonalAccessToken{Name: "forbidden ceiling", GroupID: group.ID, Permissions: []iam.Perm{permission}})
			e, ok := iam.AsError(err)
			if !ok || e.Code() != "invalid_request" || e.Param() != "permissions" {
				t.Fatalf("unsafe personal permission %s accepted or misclassified: %v", permission, err)
			}
		}
		page, err := f.auth.ListPersonalAccessTokens(t.Context(), who, iam.PageRequest{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("refused personal-token creation left credentials")
		}
	})
	t.Run("AK-J17-C03_other_owner_group_and_issuer_cannot_use_or_revoke", func(t *testing.T) {
		f := newFixture(t)
		token, group, owner := f.personal(t, f.read)
		otherGroup, otherUser, otherWho := f.ownedGroup(t)
		v, err := f.authenticate(t, token.Secret)
		noError(t, err)
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(otherGroup.ID))
		noError(t, err)
		allowed, err := v.(auth.PermissionChecker).Can(t.Context(), scope, f.read.String())
		noError(t, err)
		if allowed {
			t.Fatal("personal token crossed its bound group")
		}
		noError(t, f.auth.RevokePersonalAccessToken(t.Context(), otherWho, token.Token.ID))
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), token.Secret)
		noError(t, err)
		page, err := f.auth.ListPersonalAccessTokens(t.Context(), otherWho, iam.PageRequest{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("another owner listed the personal token")
		}
		peer := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) { c.Token.Issuer = "https://other-personal-issuer.example" }))
		_, err = peer.ResolvePersonalAccessToken(t.Context(), token.Secret)
		if !errors.Is(err, iam.ErrPersonalAccessTokenInvalid) {
			t.Fatalf("another issuer accepted personal token: %v", err)
		}
		if owner.Subject == otherUser.ID || group.ID == otherGroup.ID {
			t.Fatal("isolation fixture accidentally reused its owner/scope")
		}
	})
	t.Run("AK-J17-C04_personal_token_cannot_become_account_session_or_MFA", func(t *testing.T) {
		f := newFixture(t)
		token, _, _ := f.personal(t, f.read)
		for _, op := range []struct {
			method, path string
			body         any
		}{{"GET", "/me", nil}, {"GET", "/me/sessions", nil}, {"PATCH", "/me", map[string]string{"username": "forbiddenpat"}}, {"POST", "/me/personal-access-tokens", map[string]string{"name": "nested"}}, {"POST", "/me/step-up/password", map[string]string{"password": authtest.Password}}, {"DELETE", "/logout", nil}} {
			t.Run(op.method+op.path, func(t *testing.T) {
				f.call(t, op.method, op.path, token.Secret, op.body).want(t, http.StatusForbidden, "forbidden")
			})
		}
		claims, err := f.auth.Verify(t.Context(), token.Secret)
		noError(t, err)
		if err := f.auth.CheckRecentSignIn(t.Context(), claims); err == nil {
			t.Fatal("PAT acquired interactive freshness")
		}
	})
	t.Run("AK-J17-C05_live_owner_grants_narrow_and_ban_never_revives_tokens", func(t *testing.T) {
		f := newFixture(t)
		token, group, who := f.personal(t, f.read, f.write)
		ref := iam.GroupByID(group.ID)
		ownerToken, err := f.auth.MintAccessToken(t.Context(), who.Subject, iam.AccessTokenOptions{SessionID: who.Credential.ID})
		noError(t, err)
		r := f.call(t, "GET", "/me/personal-access-tokens", ownerToken.Value, nil)
		r.want(t, http.StatusOK, "")
		var page struct {
			Data []map[string]json.RawMessage `json:"data"`
		}
		decode(t, r.body, &page)
		if len(page.Data) != 1 || strings.Contains(string(r.body), token.Secret) {
			t.Fatal("personal-token listing hid the control or exposed its secret")
		}
		for _, field := range []string{"secret", "secret_hash"} {
			if _, ok := page.Data[0][field]; ok {
				t.Fatalf("personal-token list leaked %s", field)
			}
		}
		second := f.user(t)
		f.grant(t, group, second, f.shop.Owner)
		_, err = f.auth.SetGroupRole(t.Context(), iam.SystemIdentity(), ref, iam.UserSubject(who.Subject), f.reader)
		noError(t, err)
		resolved, err := f.auth.ResolvePersonalAccessToken(t.Context(), token.Secret)
		noError(t, err)
		if len(resolved.Permissions) != 1 || resolved.Permissions[0] != f.read {
			t.Fatal("PAT kept a permission its owner lost or lost an unaffected grant")
		}
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), who.Subject, iam.Ban{}))
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), token.Secret)
		if !errors.Is(err, iam.ErrPersonalAccessTokenInvalid) {
			t.Fatalf("banned owner's token remained valid: %v", err)
		}
		noError(t, f.auth.Unban(t.Context(), iam.SystemIdentity(), who.Subject))
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), token.Secret)
		if !errors.Is(err, iam.ErrPersonalAccessTokenInvalid) {
			t.Fatalf("unban revived retired personal token: %v", err)
		}
	})
}
