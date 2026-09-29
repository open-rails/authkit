package engine

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
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

	confirmed := f.expect(200, f.post("/verify/confirm", map[string]any{"identifier": owner, "code": sentCode(t, f.email, testoutbox.Verification)}))
	claims, err := f.service.Verifier().Verify(ctx, confirmed.AccessToken)
	require.NoError(t, err)
	userID := claims.UserID
	require.Equal(t, name, meUsername(t, f, confirmed.AccessToken), "display keeps the chosen spelling")

	// Three sign-ins fill the session cap and evict the confirmation's session;
	// the last one's token is live.
	var live string
	for _, spelling := range []string{name, lower, upper} {
		login := f.expect(200, f.post("/password/login", map[string]any{"identifier": spelling, "password": pass}))
		got, err := f.service.Verifier().Verify(ctx, login.AccessToken)
		require.NoError(t, err)
		require.Equal(t, userID, got.UserID, "login as %s", spelling)
		live = login.AccessToken
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

	evicted := f.expect(401, f.request("PATCH", "/user/username", confirmed.AccessToken, map[string]any{"username": lower}))
	require.Equal(t, "session_revoked", evicted.Error.Code, "an evicted session changes nothing")
	renamed := f.expect(200, f.request("PATCH", "/user/username", live, map[string]any{"username": lower}))
	require.Contains(t, renamed.raw, `"username":"`+lower+`"`)
	require.Equal(t, lower, meUsername(t, f, live))
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
