package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func TestGroupRemoteAppIssuerOwnership_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()
	groups := []string{"issuer-owner-a", "issuer-owner-b"}
	for _, slug := range groups {
		_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: slug, OwnerSubjectID: caller})
		require.NoError(t, err)
	}
	const issuer = "https://issuer-ownership.example"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE issuer=$1`, issuer)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug=ANY($1)`, groups)
	})
	route := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:credentials:manage"}
	register := func(group, slug, jwks string, enabled bool) (int, string) {
		body, err := json.Marshal(map[string]any{"slug": slug, "issuer": issuer, "jwks_uri": jwks, "enabled": enabled})
		require.NoError(t, err)
		w := s.drive(t, route, group, caller, string(body))
		return w.Code, w.Body.String()
	}
	code, body := register(groups[0], "issuer-owned", issuer+"/jwks.json", true)
	require.Equal(t, http.StatusCreated, code, body)
	original, err := s.svc.GetRemoteApplication(ctx, issuer)
	require.NoError(t, err)

	// A valid manager addressing their own group cannot change another group's
	// application identity, keys, or enabled state, even with a different slug.
	code, body = register(groups[1], "issuer-takeover", "https://attacker.example/jwks.json", false)
	require.Equal(t, http.StatusConflict, code, body)
	require.Contains(t, body, `"code":"remote_application_issuer_conflict"`)
	unchanged, err := s.svc.GetRemoteApplication(ctx, issuer)
	require.NoError(t, err)
	require.Equal(t, original, unchanged)

	// The owning group can still rename the application and rotate its keys.
	code, body = register(groups[0], "issuer-rotated", issuer+"/rotated.json", false)
	require.Equal(t, http.StatusCreated, code, body)
	rotated, err := s.svc.GetRemoteApplication(ctx, issuer)
	require.NoError(t, err)
	require.Equal(t, original.ID, rotated.ID)
	require.Equal(t, original.PermissionGroupID, rotated.PermissionGroupID)
	require.Equal(t, "issuer-rotated", rotated.Slug)
	require.Equal(t, issuer+"/rotated.json", rotated.JWKSURI)
	require.False(t, rotated.Enabled)
}
