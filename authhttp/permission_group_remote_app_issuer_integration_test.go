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

// #282: an issuer belongs to the group that registered it. Another group's
// credential manager cannot re-register (steal, re-key, or re-point) it via
// the plain register route; the owning group can still rotate it.
func TestGroupRemoteAppRegisterRefusesCrossGroupIssuer_HTTP(t *testing.T) {
	s, pool, ownerA := newCredTestService(t)
	ctx := context.Background()

	var ownerB string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&ownerB))
	for slug, owner := range map[string]string{"m-iss-a": ownerA, "m-iss-b": ownerB} {
		_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: slug, OwnerSubjectID: owner})
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE issuer LIKE 'https://issuer.ci.example/x282%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug IN ('m-iss-a','m-iss-b')`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, ownerB)
	})
	groupA, err := s.svc.ResolveGroupIDForSlug(ctx, "merchant", "m-iss-a")
	require.NoError(t, err)

	regGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:credentials:manage"}
	const issuer = "https://issuer.ci.example/x282"
	const jwksA = "https://issuer.ci.example/a/jwks.json"
	rowState := func(t *testing.T) (slug, gid, jwks string) {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx, `SELECT slug, permission_group_id::text, jwks_uri FROM profiles.remote_applications WHERE issuer=$1`, issuer).Scan(&slug, &gid, &jwks))
		return
	}

	w := s.drive(t, regGR, "m-iss-a", ownerA, `{"slug":"ci-x282-a","issuer":"`+issuer+`","jwks_uri":"`+jwksA+`"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Group B: victim issuer under a fresh or the victim's own slug, attacker
	// keys -> 409 and the row is untouched.
	for _, body := range []string{
		`{"slug":"ci-x282-b","issuer":"` + issuer + `","jwks_uri":"https://attacker.example/jwks.json"}`,
		`{"slug":"ci-x282-a","issuer":"` + issuer + `","jwks_uri":"https://attacker.example/jwks.json","enabled":false}`,
	} {
		w = s.drive(t, regGR, "m-iss-b", ownerB, body)
		require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
		var env authkit.ErrorEnvelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		require.Equal(t, string(ErrRemoteApplicationIssuerConflict), env.Error.Code)
		slug, gid, jwks := rowState(t)
		require.Equal(t, "ci-x282-a", slug)
		require.Equal(t, groupA, gid)
		require.Equal(t, jwksA, jwks)
	}

	// The owning group still rotates its own issuer.
	w = s.drive(t, regGR, "m-iss-a", ownerA, `{"slug":"ci-x282-a","issuer":"`+issuer+`","jwks_uri":"https://issuer.ci.example/a/rotated.json"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	_, gid, jwks := rowState(t)
	require.Equal(t, groupA, gid)
	require.Equal(t, "https://issuer.ci.example/a/rotated.json", jwks)
}
