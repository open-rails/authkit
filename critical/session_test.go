package critical_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

func TestCriticalSessions(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J05-C01_concurrent_refresh_has_one_successor", func(t *testing.T) {
		u := f.user(t)
		old := f.signIn(t, u)
		if old.RefreshToken == nil {
			t.Fatal("non-cookie login omitted refresh token")
		}
		body := map[string]string{"grant_type": "refresh_token", "refresh_token": *old.RefreshToken}
		responses := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range responses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				responses[i], errs[i] = f.request(t.Context(), "POST", "/token", "", body)
			}()
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			noError(t, err)
		}
		one, two := tokensFrom(t, responses[0], u.ID), tokensFrom(t, responses[1], u.ID)
		if one.RefreshToken == nil || two.RefreshToken == nil || *one.RefreshToken != *two.RefreshToken || *one.RefreshToken == *old.RefreshToken {
			t.Fatal("concurrent refresh forked or failed to rotate its successor")
		}
		c1, err := f.auth.Verify(t.Context(), one.AccessToken)
		noError(t, err)
		c2, err := f.auth.Verify(t.Context(), two.AccessToken)
		noError(t, err)
		if c1.SessionID == "" || c1.SessionID != c2.SessionID {
			t.Fatal("refresh created independent session authority")
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 1 || live[0].ID != c1.SessionID {
			t.Fatalf("refresh session state = %+v", live)
		}
		// Retrying the unacknowledged predecessor returns that same successor.
		retry := tokensFrom(t, f.call(t, "POST", "/token", "", body), u.ID)
		if retry.RefreshToken == nil || *retry.RefreshToken != *one.RefreshToken {
			t.Fatal("lost-response retry forked the rotation chain")
		}
	})
	t.Run("AK-J05-C02_revoke_other_then_all_sessions", func(t *testing.T) {
		u := f.user(t)
		one, two := f.signIn(t, u), f.signIn(t, u)
		other, err := f.auth.Verify(t.Context(), two.AccessToken)
		noError(t, err)
		f.call(t, "DELETE", "/me/sessions/"+other.SessionID, one.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", two.AccessToken, map[string]string{"username": "revokedwriter"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "GET", "/me/sessions", one.AccessToken, nil).want(t, http.StatusOK, "")
		who := f.identity(t, one.AccessToken)
		_, err = f.auth.RevokeAccountSessions(t.Context(), who, u.ID)
		noError(t, err)
		for _, token := range []string{one.AccessToken, two.AccessToken} {
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
				t.Fatal("account revoke left a session usable")
			}
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 0 {
			t.Fatal("revoked sessions remained in live listing")
		}
	})
	t.Run("AK-J05-C03_password_and_ban_retire_live_authority", func(t *testing.T) {
		u := f.user(t)
		current, other := f.signIn(t, u), f.signIn(t, u)
		const changed = "Changed-critical-password-2"
		f.call(t, "PUT", "/me/password", current.AccessToken, map[string]string{"new_password": changed}).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", other.AccessToken, map[string]string{"username": "oldcredential"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "invalid_credentials")
		u.Password = changed
		newTokens := f.signIn(t, u)
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		claims, err := f.auth.Verify(t.Context(), newTokens.AccessToken)
		noError(t, err)
		if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
			t.Fatal("ban preserved live authority")
		}
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": changed}).want(t, http.StatusUnauthorized, "user_banned")
	})
	t.Run("AK-J05-C04_stateless_signature_is_not_live_session_authority", func(t *testing.T) {
		u := f.user(t)
		tokens := f.signIn(t, u)
		claims, err := f.auth.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if claims.UserID != u.ID || claims.SessionID == "" {
			t.Fatal("sign-in token did not bind the expected user and session")
		}
		who := f.identity(t, tokens.AccessToken)
		noError(t, f.auth.RevokeSession(t.Context(), who, u.ID, claims.SessionID))
		// An old JWT remains cryptographically valid; privileged requests must
		// nevertheless consult the now-revoked sign-in.
		_, err = f.auth.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if err := f.auth.CheckSession(t.Context(), claims); !errors.Is(err, iam.ErrSessionRevoked) {
			t.Fatalf("revoked session error = %v", err)
		}
		f.call(t, "PATCH", "/me", tokens.AccessToken, map[string]string{"username": "mustnotpersist"}).want(t, http.StatusUnauthorized, "session_revoked")
		r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/identity", nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		if _, err = f.auth.Authenticator().Authenticate(r); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("live authenticator must classify revoked authority: %v", err)
		}
		current, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if current.Username != u.Username {
			t.Fatal("refused mutation changed the public account state")
		}
	})
	t.Run("AK-J05-C06_member_checks_read_account_and_session_once_per_call", func(t *testing.T) {
		f, log := newTracedFixture(t)
		g, _, _ := f.ownedGroup(t)
		refs := []iam.GroupRef{iam.RootGroup(), iam.GroupByID(f.tenant.String()), iam.GroupByID(g.ID)}
		request := func(ctx context.Context, token string) *http.Request {
			r, err := http.NewRequestWithContext(ctx, "GET", f.server.URL+"/member", nil)
			noError(t, err)
			r.Header.Set("Authorization", "Bearer "+token)
			return r
		}
		// The hosts' tenant member gate: a live sign-in, then its source account.
		member := func(ctx context.Context, token string) (iam.TenantActor, error) {
			verified, err := verify.AuthenticateSession(ctx, f.auth, request(ctx, token))
			if err != nil {
				return iam.TenantActor{}, err
			}
			return f.auth.ResolveTenantActor(ctx, verified)
		}
		signedIn := func(t *testing.T) (string, string, auth.Verified) {
			u := f.user(t)
			f.grant(t, g, u, f.reader)
			token := f.signIn(t, u).AccessToken
			verified, err := verify.AuthenticateSession(t.Context(), f.auth, request(t.Context(), token))
			noError(t, err)
			return u.ID, token, verified
		}
		exec := func(t *testing.T, sql string, args ...any) {
			tag, err := f.pool.Exec(t.Context(), sql, args...)
			noError(t, err)
			if tag.RowsAffected() != 1 {
				t.Fatalf("fixture update touched %d rows", tag.RowsAffected())
			}
		}
		table := func(name string) string { return pgx.Identifier{f.schema, name}.Sanitize() }

		id, token, verified := signedIn(t)
		for range 2 { // the second round runs on warm caches and connections
			var actor iam.TenantActor
			sent := log.during(t.Context(), func(ctx context.Context) {
				var err error
				actor, err = member(ctx, token)
				noError(t, err)
			})
			if actor != (iam.TenantActor{AccountID: id, TenantID: f.tenant}) {
				t.Fatalf("member resolved %+v", actor)
			}
			if len(sent) > 2 {
				t.Errorf("tenant member gate sent %d statements, want at most 2: %v", len(sent), sent)
			}
			var perms map[string][]iam.Perm
			sent = log.during(t.Context(), func(ctx context.Context) {
				var err error
				perms, err = f.auth.EffectivePermissions(ctx, verified.Identity(), refs)
				noError(t, err)
			})
			if len(perms[g.ID]) == 0 {
				t.Fatalf("live member lost its grant: %v", perms)
			}
			if len(sent) > 2 {
				t.Errorf("EffectivePermissions sent %d statements, want at most 2: %v", len(sent), sent)
			}
			sent = log.during(t.Context(), func(ctx context.Context) {
				ok, err := f.auth.Can(ctx, verified.Identity(), iam.GroupByID(g.ID), f.read)
				noError(t, err)
				if !ok {
					t.Fatal("live member cannot use its grant")
				}
			})
			if len(sent) > 3 {
				t.Errorf("Can sent %d statements, want at most 3: %v", len(sent), sent)
			}
		}

		// revoked is every check refusing a sign-in that no longer stands.
		revoked := func(t *testing.T, token string, verified auth.Verified) {
			t.Helper()
			if actor, err := member(t.Context(), token); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted %+v: %v", actor, err)
			}
			if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
				t.Fatalf("retained credential resolved %+v: %v", actor, err)
			}
			if perms, err := f.auth.EffectivePermissions(t.Context(), verified.Identity(), refs); !errors.Is(err, iam.ErrSessionRevoked) || len(perms) != 0 {
				t.Fatalf("EffectivePermissions kept %v: %v", perms, err)
			}
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); !errors.Is(err, iam.ErrSessionRevoked) || ok {
				t.Fatalf("Can kept %v: %v", ok, err)
			}
		}
		t.Run("signed_out", func(t *testing.T) {
			_, token, verified := signedIn(t)
			f.call(t, "DELETE", "/logout", token, nil).want(t, http.StatusNoContent, "")
			revoked(t, token, verified)
		})
		t.Run("session_revoked", func(t *testing.T) {
			id, token, verified := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			noError(t, f.auth.RevokeSession(t.Context(), iam.SystemIdentity(), id, claims.SessionID))
			revoked(t, token, verified)
		})
		t.Run("session_expired", func(t *testing.T) {
			_, token, verified := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			exec(t, "UPDATE "+table("refresh_sessions")+" SET expires_at = now() - interval '1 microsecond' WHERE id = $1", claims.SessionID)
			revoked(t, token, verified)
		})
		t.Run("banned", func(t *testing.T) {
			id, token, verified := signedIn(t)
			noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), id, iam.Ban{}))
			revoked(t, token, verified)
		})
		t.Run("deleted", func(t *testing.T) {
			id, token, verified := signedIn(t)
			results, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{id})
			noError(t, err)
			if len(results) != 1 || results[0].Err != nil {
				t.Fatalf("delete results %+v", results)
			}
			revoked(t, token, verified)
		})
		// The account checks refuse alone, before its sign-in is revoked.
		t.Run("deleted_with_sign_in_row_still_live", func(t *testing.T) {
			id, token, verified := signedIn(t)
			exec(t, "UPDATE "+table("users")+" SET deleted_at = now() WHERE id = $1", id)
			if actor, err := member(t.Context(), token); !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted a deleted account: %+v, %v", actor, err)
			}
			if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
				t.Fatalf("deleted account resolved %+v: %v", actor, err)
			}
			if perms, err := f.auth.EffectivePermissions(t.Context(), verified.Identity(), refs); err != nil || len(perms) != 0 {
				t.Fatalf("deleted account kept %v: %v", perms, err)
			}
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); !errors.Is(err, iam.ErrSessionRevoked) || ok {
				t.Fatalf("deleted account kept Can %v: %v", ok, err)
			}
		})
		t.Run("banned_with_sign_in_row_still_live", func(t *testing.T) {
			id, token, verified := signedIn(t)
			exec(t, "UPDATE "+table("users")+" SET banned_at = now() WHERE id = $1", id)
			if actor, err := member(t.Context(), token); !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted a banned account: %+v, %v", actor, err)
			}
			if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
				t.Fatalf("banned account resolved %+v: %v", actor, err)
			}
			if perms, err := f.auth.EffectivePermissions(t.Context(), verified.Identity(), refs); err != nil || len(perms) != 0 {
				t.Fatalf("banned account kept %v: %v", perms, err)
			}
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); err != nil || ok {
				t.Fatalf("banned account kept Can %v: %v", ok, err)
			}
		})
		other := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: other, Slug: "member-other"}))
		// Accounts never change tenant, so only claims naming another tenant
		// reach this refusal.
		t.Run("claims_naming_another_tenant", func(t *testing.T) {
			_, token, _ := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			noError(t, f.auth.CheckSession(t.Context(), claims))
			for _, tenant := range []string{other.String(), "not-a-tenant"} {
				claims.TenantID = tenant
				if err := f.auth.CheckSession(t.Context(), claims); !errors.Is(err, iam.ErrSessionRevoked) {
					t.Fatalf("claims for tenant %q kept a live session: %v", tenant, err)
				}
			}
		})
		t.Run("another_tenant_member_is_not_this_tenant", func(t *testing.T) {
			view, err := f.auth.ForTenant(t.Context(), other)
			noError(t, err)
			server := httptest.NewServer(view.Handler())
			t.Cleanup(server.Close)
			outsider := &fixture{auth: view, server: server}
			u := outsider.user(t)
			token := outsider.signIn(t, u).AccessToken
			actor, err := member(t.Context(), token)
			noError(t, err)
			if actor != (iam.TenantActor{AccountID: u.ID, TenantID: other}) {
				t.Fatalf("another tenant's member resolved as %+v", actor)
			}
			verified, err := verify.AuthenticateSession(t.Context(), f.auth, request(t.Context(), token))
			noError(t, err)
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); err != nil || ok {
				t.Fatalf("another tenant's member gained Can %v: %v", ok, err)
			}
		})
	})
	t.Run("AK-J05-C05_late_refresh_cannot_undo_logout", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		if session.RefreshToken == nil {
			t.Fatal("missing refresh token")
		}
		f.call(t, "DELETE", "/logout", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/token", "", map[string]string{"grant_type": "refresh_token", "refresh_token": *session.RefreshToken}).want(t, http.StatusUnauthorized, "invalid_token")
		f.call(t, "DELETE", "/logout", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", session.AccessToken, map[string]string{"username": "latewriter"}).want(t, http.StatusUnauthorized, "session_revoked")
		fresh := f.signIn(t, u)
		oldClaims, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		newClaims, err := f.auth.Verify(t.Context(), fresh.AccessToken)
		noError(t, err)
		if oldClaims.SessionID == newClaims.SessionID {
			t.Fatal("fresh sign-in revived a retired session")
		}
	})
}
