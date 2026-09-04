package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func namingHTTPServer(t *testing.T, policy authkit.NamingConfig, opts ...embedded.Option) (*Service, *embedded.Client, func(time.Time)) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	cfg.Naming = policy
	cfg.RBAC[1].Capabilities.APIKeys = true
	var clock atomic.Int64
	clock.Store(time.Now().UTC().Truncate(time.Microsecond).UnixMicro())
	opts = append(opts, embedded.WithNamingClock(func() time.Time { return time.UnixMicro(clock.Load()).UTC() }))
	client, err := embedded.New(cfg, pg.Pool, opts...)
	require.NoError(t, err)
	require.NoError(t, client.SeedPermissionGroupContainment(context.Background()))
	_, err = client.EnsureRootGroup(context.Background())
	require.NoError(t, err)
	srv, err := NewServer(client, WithoutRateLimiter())
	require.NoError(t, err)
	return srv, client, func(now time.Time) { clock.Store(now.UnixMicro()) }
}

func TestNamingHTTPPolicyAndCompositeSettings(t *testing.T) {
	srv, client, setTime := namingHTTPServer(t, authkit.NamingConfig{})
	owner, token := newInstanceTestUser(t, srv, "namingowner")
	require.Equal(t, http.StatusCreated, postOrg(srv, token, `{"slug":"original","display_name":"Before"}`).Code)
	original, err := client.GroupInstanceForSlug(context.Background(), "org", "original")
	require.NoError(t, err)
	w := serveAuthJSON(srv, http.MethodPatch, "/org/original", `{"slug":"renamed","display_name":"After"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), original.ID)
	var body struct {
		Naming authkit.NamingState `json:"naming"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Naming.Aliases, 1)
	require.Equal(t, "original", body.Naming.Aliases[0].Name)
	require.NotNil(t, body.Naming.Aliases[0].ExpiresAt)
	require.False(t, body.Naming.Allowed)
	require.Equal(t, int64(72*60*60), body.Naming.RetryAfterSeconds)
	w = serveAuthJSON(srv, http.MethodPatch, "/org/original", `{"slug":"blocked","display_name":"Must roll back"}`, token)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "next_rename_at")
	current, err := client.GroupInstanceForSlug(context.Background(), "org", "renamed")
	require.NoError(t, err)
	require.Equal(t, "After", current.DisplayName)
	// No-op rename through an alias still allows an atomic display-only change.
	w = serveAuthJSON(srv, http.MethodPatch, "/org/original", `{"slug":"renamed","display_name":"No-op name"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	setTime(*body.Naming.NextRenameAt)
	w = serveAuthJSON(srv, http.MethodPatch, "/org/original", `{"slug":"third"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	user, err := client.UsersByIDs(context.Background(), []string{owner})
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPatch, "/user/username", `{"username":"username_updated"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "259200")
	w = serveAuthJSON(srv, http.MethodPatch, "/user/username", `{"username":"username_blocked"}`, token)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	resolved, err := client.ResolveUsername(context.Background(), user[owner].Username)
	require.NoError(t, err)
	require.Equal(t, owner, resolved.ID)
}

func TestNamingHTTPDisabledAndHostAdmission(t *testing.T) {
	disabled := false
	srv, _, _ := namingHTTPServer(t, authkit.NamingConfig{Enabled: &disabled})
	_, token := newInstanceTestUser(t, srv, "disablednames")
	require.Equal(t, http.StatusCreated, postOrg(srv, token, `{"slug":"fixed"}`).Code)
	w := serveAuthJSON(srv, http.MethodPatch, "/org/fixed", `{"slug":"changed"}`, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "renames_disabled")
	w = serveAuthJSON(srv, http.MethodPatch, "/user/username", `{"username":"changed_user"}`, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var creationCosts atomic.Int64
	var admissions []authkit.NameAdmissionRequest
	next, _, _ := namingHTTPServer(t, authkit.NamingConfig{}, embedded.WithInstanceAdmission(func(context.Context, string, string, string) error { creationCosts.Add(1); return nil }), embedded.WithNameAdmission(func(_ context.Context, r authkit.NameAdmissionRequest) error {
		admissions = append(admissions, r)
		if r.RequestedName == "blocked" {
			return errors.New("host-owned name")
		}
		return nil
	}))
	owner, nextToken := newInstanceTestUser(t, next, "admitted")
	require.Equal(t, http.StatusForbidden, postOrg(next, nextToken, `{"slug":"blocked"}`).Code)
	require.Equal(t, http.StatusCreated, postOrg(next, nextToken, `{"slug":"allowed"}`).Code)
	w = serveAuthJSON(next, http.MethodPatch, "/org/allowed", `{"slug":"blocked"}`, nextToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = serveAuthJSON(next, http.MethodPatch, "/org/allowed", `{"slug":"renamed"}`, nextToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, int64(1), creationCosts.Load(), "rename must not run creation cost hook")
	last := admissions[len(admissions)-1]
	require.Equal(t, authkit.NameRename, last.Operation)
	require.Equal(t, owner, last.ActorID)
	require.NotEmpty(t, last.OwnerID)
	require.Equal(t, "allowed", last.CurrentName)
}

func TestNamingHTTPRequestsKeepAuthorizedGroupAfterReuse(t *testing.T) {
	zero := time.Duration(0)
	srv, client, _ := namingHTTPServer(t, authkit.NamingConfig{RenameInterval: &zero, FormerNames: authkit.FormerNameRetentionConfig{Mode: authkit.FormerNamesImmediate}})
	first, firstToken := newInstanceTestUser(t, srv, "firstowner")
	_, secondToken := newInstanceTestUser(t, srv, "secondowner")
	require.Equal(t, http.StatusCreated, postOrg(srv, firstToken, `{"slug":"reusable"}`).Code)
	original, err := client.GroupInstanceForSlug(context.Background(), "org", "reusable")
	require.NoError(t, err)
	// This is the context captured by generatedGroupHandler before authorization.
	captured := authcore.WithResolvedGroup(context.Background(), original, "reusable")
	renamed := "moved"
	_, err = client.UpdateGroupInstanceAs(context.Background(), first, original.ID, authkit.GroupInstanceUpdate{Slug: &renamed})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, postOrg(srv, secondToken, `{"slug":"reusable"}`).Code)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(captured)
		r.Header.Set("Authorization", "Bearer "+firstToken)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.APIHandler().ServeHTTP(w, r)
		return w
	}
	for _, suffix := range []string{"/members", "/api-keys", "/remote-applications", "/invites/links"} {
		w := request(http.MethodGet, "/org/reusable"+suffix, "")
		require.Equal(t, http.StatusOK, w.Code, suffix+" "+w.Body.String())
		require.Equal(t, original.ID, w.Header().Get("X-AuthKit-Group-ID"))
		fresh := serveAuthJSON(srv, http.MethodGet, "/org/reusable"+suffix, "", firstToken)
		require.Equal(t, http.StatusForbidden, fresh.Code, suffix+" fresh "+fresh.Body.String())
	}
	w := request(http.MethodPost, "/org/reusable/api-keys", `{"name":"captured-key","role":"member"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	keys, err := srv.svc.ListAPIKeys(context.Background(), "org", "moved")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "captured-key", keys[0].Name)
	keys, err = srv.svc.ListAPIKeys(context.Background(), "org", "reusable")
	require.NoError(t, err)
	require.Empty(t, keys)
	// A deleted captured identity refuses rather than falling back to the claimant.
	require.NoError(t, client.DeletePermissionGroup(context.Background(), "org", "moved", authkit.DeletePermissionGroupOptions{ReleaseSlug: true}))
	w = request(http.MethodGet, "/org/reusable/members", "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
