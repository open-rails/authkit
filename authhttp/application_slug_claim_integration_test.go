package authhttp

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

// #296: a self-registering application cannot claim a slug the org persona
// reserves; the same domain registers fine under a non-reserved slug.
func TestApplicationSelfRegistration_RefusesReservedSlug(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	cfg := newServerTestConfig()
	cfg.RBAC = []embedded.PersonaDef{{
		Name: "org", Parent: "root",
		Creation: embedded.InstanceCreationDef{ReservedSlugs: []string{"cozy-art"}},
	}}
	cfg.Applications = embedded.ApplicationsConfig{SelfRegistration: true, OrgPersona: "org"}
	client := newServerClient(t, cfg, pool)
	s, err := NewServer(client)
	require.NoError(t, err)
	require.NoError(t, embedded.Unwrap(client).SeedPermissionGroupContainment(ctx))
	h, err := MountHandler(s, MountOptions{})
	require.NoError(t, err)

	key, err := jwtkit.NewRSASigner(2048, "key-reserved")
	require.NoError(t, err)
	docSrv := newDocServer(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE issuer = $1`, docSrv.srv.URL)
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_groups WHERE persona = 'org' AND instance_slug IN ('cozy-art', $1)`, "cozy-art-"+suffix)
	})

	docSrv.set(authkit.ApplicationDocument{Slug: "cozy-art", Issuer: docSrv.srv.URL, PublicKeys: []authkit.RemoteAppKey{staticKey(t, key)}})
	rec, body := postJSON(t, h, "/api/v1/applications/register", map[string]any{"domain": docSrv.srv.URL})
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Equal(t, string(ErrApplicationSlugConflict), body["error"].(map[string]any)["code"])
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.remote_applications WHERE issuer = $1`, docSrv.srv.URL).Scan(&n))
	require.Zero(t, n, "a refused claim must not register anything")
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.permission_groups WHERE persona = 'org' AND instance_slug = 'cozy-art'`).Scan(&n))
	require.Zero(t, n, "a refused claim must not create the service org")

	docSrv.set(authkit.ApplicationDocument{Slug: "cozy-art-" + suffix, Issuer: docSrv.srv.URL, PublicKeys: []authkit.RemoteAppKey{staticKey(t, key)}})
	rec, _ = postJSON(t, h, "/api/v1/applications/register", map[string]any{"domain": docSrv.srv.URL})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
}
