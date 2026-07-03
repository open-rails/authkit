package authhttp

import (
	"context"
	"encoding/json"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// #147 known-user consent invite, end to end over HTTP: an owner invites an
// EXISTING user (invite=true → no silent add), the invitee sees it on
// /me/group-invites, and accepting it (with the invitee's OWN auth) grants the role.
func TestGroupMembershipInvite_HTTP_AcceptFlow(t *testing.T) {
	s, pool, owner := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-invite", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_membership_invites`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-invite'`)
	})

	var target string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&target))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, target) })

	// Owner POSTs the member add with invite=true → a pending invite, NOT a grant.
	addBody, _ := json.Marshal(map[string]any{"user_id": target, "role": "member", "invite": true})
	r := httptest.NewRequest(http.MethodPost, "http://x/merchant/m-invite/members", strings.NewReader(string(addBody)))
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: owner}))
	w := httptest.NewRecorder()
	s.groupMemberAdd(w, r, "merchant", "m-invite")
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	if ok, _ := s.svc.Can(ctx, target, embedded.SubjectKindUser, "merchant", "m-invite", "merchant:catalog:read"); ok {
		t.Fatal("target must not hold the role before accepting")
	}

	// Invitee lists their pending invites (own auth) and finds it.
	r = httptest.NewRequest(http.MethodGet, "http://x/me/group-invites", nil)
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: target}))
	w = httptest.NewRecorder()
	s.handleMeGroupInvitesGET(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listResp struct {
		Data []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
	require.Len(t, listResp.Data, 1)
	require.Equal(t, "member", listResp.Data[0].Role)
	inviteID := listResp.Data[0].ID

	// Invitee accepts (own auth) → role granted.
	r = httptest.NewRequest(http.MethodPost, "http://x/me/group-invites/"+inviteID+"/accept", nil)
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: target}))
	r.SetPathValue("id", inviteID)
	w = httptest.NewRecorder()
	s.handleMeGroupInviteAccept(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	ok, err := s.svc.Can(ctx, target, embedded.SubjectKindUser, "merchant", "m-invite", "merchant:catalog:read")
	require.NoError(t, err)
	require.True(t, ok, "target should hold the role after accepting")
}
