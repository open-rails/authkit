package engine

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A username is one identity in every case: the owner's spelling is kept for
// display, and registration, pending holds, login and availability all treat
// other spellings as that same account.
func TestUsernameCaseWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.Verification = iam.RegistrationVerificationRequired
	f := newAccountFlow(t, pg.Pool, cfg)
	ctx := t.Context()
	suffix := uniqueSuffix()
	name := "Fidika" + suffix[len(suffix)-8:]
	lower, upper := strings.ToLower(name), strings.ToUpper(name)
	const pass = "Correct-horse-battery-1"
	owner := uniqueEmail("case-owner")

	f.expect(202, f.post("/register", map[string]any{"identifier": owner, "username": name, "password": pass}))
	held := f.expect(400, f.post("/register", map[string]any{"identifier": uniqueEmail("case-pending"), "username": lower, "password": pass}))
	require.Equal(t, "username_in_use", held.Error.Code, "a pending signup holds every spelling of its name")

	confirmed := f.expect(200, f.post("/verify/confirm", map[string]any{"identifier": owner, "code": f.email.verificationCode(t)}))
	claims, err := f.service.Verifier().Verify(ctx, confirmed.AccessToken)
	require.NoError(t, err)
	userID := claims.UserID
	require.Equal(t, name, meUsername(t, f, confirmed.AccessToken), "display keeps the chosen spelling")

	for _, spelling := range []string{name, lower, upper} {
		login := f.expect(200, f.post("/password/login", map[string]any{"identifier": spelling, "password": pass}))
		got, err := f.service.Verifier().Verify(ctx, login.AccessToken)
		require.NoError(t, err)
		require.Equal(t, userID, got.UserID, "login as %s", spelling)
	}

	taken := f.expect(400, f.post("/register", map[string]any{"identifier": uniqueEmail("case-dup"), "username": upper, "password": pass}))
	require.Equal(t, "username_in_use", taken.Error.Code)
	var accounts int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(username::text)=$1`, lower).Scan(&accounts))
	require.Equal(t, 1, accounts)

	availability := f.expect(200, f.request("GET", "/register/availability?username="+url.QueryEscape(lower), "", nil))
	var answer struct {
		Username struct {
			Available bool `json:"available"`
		} `json:"username"`
	}
	require.NoError(t, json.Unmarshal([]byte(availability.raw), &answer))
	require.False(t, answer.Username.Available)

	renamed := f.expect(200, f.request("PATCH", "/user/username", confirmed.AccessToken, map[string]any{"username": lower}))
	require.Contains(t, renamed.raw, `"username":"`+lower+`"`)
	require.Equal(t, lower, meUsername(t, f, confirmed.AccessToken))
	var cooled bool
	var claimsHeld int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT last_renamed_at IS NOT NULL, (SELECT count(*) FROM name_claims WHERE owner_kind='user' AND owner_id=users.id) FROM users WHERE id=$1::uuid`, userID).Scan(&cooled, &claimsHeld))
	require.False(t, cooled, "a case change is not a rename")
	require.Equal(t, 1, claimsHeld, "a case change leaves no alias")
	f.expect(200, f.post("/password/login", map[string]any{"identifier": name, "password": pass}))
}

func meUsername(t *testing.T, f *accountFlow, token string) string {
	t.Helper()
	me := f.expect(200, f.request("GET", "/me", token, nil))
	var body struct {
		Username string `json:"username"`
	}
	require.NoError(t, json.Unmarshal([]byte(me.raw), &body), me.raw)
	return body.Username
}

// Group instance slugs are stored lowercase; every entry point folds the case a
// caller sends instead of refusing it.
func TestGroupInstanceSlugCaseWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	runtime := newServerClient(t, instanceCreateTestConfig(), pg.Pool)
	service, err := newTestService(runtime, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(service.Close)
	ctx := t.Context()
	ownerID, ownerToken := newInstanceTestUser(t, service, "slugowner")
	_, otherToken := newInstanceTestUser(t, service, "slugother")

	created := postOrg(service, ownerToken, `{"slug":"Acme-Case"}`)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var instance struct {
		GroupID      string `json:"group_id"`
		InstanceSlug string `json:"instance_slug"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &instance))
	require.Equal(t, "acme-case", instance.InstanceSlug)

	read := serveAuthJSON(service, http.MethodGet, "/org/ACME-CASE", "", ownerToken)
	require.Equal(t, http.StatusOK, read.Code, read.Body.String())
	require.Contains(t, read.Body.String(), instance.GroupID)

	rerun := postOrg(service, ownerToken, `{"slug":"acme-case"}`)
	require.Equal(t, http.StatusOK, rerun.Code, rerun.Body.String())
	require.Contains(t, rerun.Body.String(), instance.GroupID)
	taken := postOrg(service, otherToken, `{"slug":"ACME-case"}`)
	require.Equal(t, http.StatusConflict, taken.Code, taken.Body.String())

	permissions := serveAuthJSON(service, http.MethodGet, "/me/permissions?persona=org&instance=Acme-CASE", "", ownerToken)
	require.Equal(t, http.StatusOK, permissions.Code, permissions.Body.String())
	require.Contains(t, permissions.Body.String(), "org:*")

	client := runtime
	hosted, err := seedGroup(ctx, client, "org", "Host-Made", ownerID)
	require.NoError(t, err)
	resolved, err := groupIDOf(ctx, client, iam.GroupBySlug("org", "host-MADE"))
	require.NoError(t, err)
	require.Equal(t, hosted, resolved)
	var groups int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM permission_groups WHERE persona='org' AND lower(instance_slug) IN ('acme-case','host-made')`).Scan(&groups))
	require.Equal(t, 2, groups)
}
