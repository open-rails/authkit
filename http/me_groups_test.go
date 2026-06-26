package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/stretchr/testify/require"
)

// newConsentTestService builds a DB-backed http.Service whose schema has a
// RequireConsent persona ("team") and an instant one ("repo"), plus an owner user.
func newConsentTestService(t *testing.T) (s *Service, owner string) {
	t.Helper()
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := embedded.Config{
		Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		RBAC: []embedded.PersonaDef{
			{Name: "team", Parent: embedded.RootPersona, RequireConsent: true,
				Roles: []embedded.RoleDef{{Name: "member", Permissions: []string{"team:catalog:read"}}}},
			{Name: "repo", Parent: embedded.RootPersona,
				Roles: []embedded.RoleDef{{Name: "member", Permissions: []string{"repo:catalog:read"}}}},
		},
	}
	coreSvc, err := authcore.NewFromConfig(cfg, pool)
	require.NoError(t, err)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&owner))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_membership_invites`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona IN ('team','repo')`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, owner)
	})
	return &Service{svc: coreSvc}, owner
}

func mkUser(t *testing.T, s *Service) string {
	t.Helper()
	var id string
	require.NoError(t, s.svc.Postgres().QueryRow(context.Background(), `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&id))
	t.Cleanup(func() {
		_, _ = s.svc.Postgres().Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, id)
	})
	return id
}

func memberAdd(t *testing.T, s *Service, persona, instance, owner, target string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"user_id": target, "role": "member"}) // NOTE: invite NOT set
	r := httptest.NewRequest(http.MethodPost, "http://x/"+persona+"/"+instance+"/members", strings.NewReader(string(body)))
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: owner}))
	w := httptest.NewRecorder()
	s.groupMemberAdd(w, r, persona, instance)
	return w
}

// TestRequireConsent_HTTP_ForcesInvite proves the per-persona join policy (#193):
// adding an existing user without invite=true is INSTANT for a normal persona but
// is upgraded to a consent invite for a RequireConsent persona — you can't silently
// drop someone into it.
func TestRequireConsent_HTTP_ForcesInvite(t *testing.T) {
	s, owner := newConsentTestService(t)
	ctx := context.Background()
	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "team", InstanceSlug: "t1", OwnerSubjectID: owner})
	require.NoError(t, err)
	_, err = s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "repo", InstanceSlug: "r1", OwnerSubjectID: owner})
	require.NoError(t, err)

	// RequireConsent persona: a plain add (no invite flag) becomes a pending invite,
	// NOT a grant.
	target := mkUser(t, s)
	w := memberAdd(t, s, "team", "t1", owner, target)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"invited":true`)
	ok, err := s.svc.Can(ctx, target, embedded.SubjectKindUser, "team", "t1", "team:catalog:read")
	require.NoError(t, err)
	require.False(t, ok, "RequireConsent persona must not silently grant the role")

	// Instant persona: the same plain add grants immediately.
	target2 := mkUser(t, s)
	w = memberAdd(t, s, "repo", "r1", owner, target2)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	ok, err = s.svc.Can(ctx, target2, embedded.SubjectKindUser, "repo", "r1", "repo:catalog:read")
	require.NoError(t, err)
	require.True(t, ok, "instant persona should grant the role directly")
}

// TestMeGroupLeave_HTTP drives the self-leave route end to end: a member removes
// themself (200, role gone), and the sole owner is refused (409 last-owner).
func TestMeGroupLeave_HTTP(t *testing.T) {
	s, owner := newConsentTestService(t)
	ctx := context.Background()
	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "repo", InstanceSlug: "leave1", OwnerSubjectID: owner})
	require.NoError(t, err)

	// Add a member instantly (repo is non-consent), then they leave with their own auth.
	member := mkUser(t, s)
	require.Equal(t, http.StatusOK, memberAdd(t, s, "repo", "leave1", owner, member).Code)
	ok, _ := s.svc.Can(ctx, member, embedded.SubjectKindUser, "repo", "leave1", "repo:catalog:read")
	require.True(t, ok)

	leave := func(uid string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "http://x/me/groups/repo/leave1", nil)
		r = r.WithContext(setClaims(r.Context(), Claims{UserID: uid}))
		r.SetPathValue("persona", "repo")
		r.SetPathValue("instance_slug", "leave1")
		w := httptest.NewRecorder()
		s.handleMeGroupLeave(w, r)
		return w
	}

	w := leave(member)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	ok, _ = s.svc.Can(ctx, member, embedded.SubjectKindUser, "repo", "leave1", "repo:catalog:read")
	require.False(t, ok, "member should hold no role after leaving")

	// The sole owner cannot leave — would orphan the group (409 cannot_remove_last_owner).
	w = leave(owner)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "cannot_remove_last_owner")
	ok, _ = s.svc.Can(ctx, owner, embedded.SubjectKindUser, "repo", "leave1", "repo:catalog:read")
	require.True(t, ok, "owner must keep authority after a refused leave")
}
