package engine

// Setup for the engine's own tests: engines on real PostgreSQL, the mounted
// HTTP surface for lock races, and shortcuts to state production reaches only
// through its flows. Black-box tests of the Client live in internal/apitest.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/helpers/auth"
)

// testSigner is one RSA key for the package's engines: explicit keys, since
// AllowEphemeralDevKeys persists a keypair under the package directory.
var testSigner = sync.OnceValue(func() keys.Signer {
	s := testkeys.RSA("test-kid")
	return s
})

// testKeys signs with testSigner.
func testKeys() keys.Source { return testkeys.Source(testSigner()) }

// testTOTPKey encrypts the test engines' authenticator-app secrets.
var testTOTPKey = []byte("0123456789abcdef0123456789abcdef")

// testConfig is an engine that signs tokens (newTestEngine supplies testKeys),
// serves HTTP and can enroll TOTP.
func testConfig() config.Config {
	return config.Config{
		Token: config.TokenConfig{
			Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"},
			// The fake IdPs and JWKS endpoints are loopback servers.
			AllowPrivateNetworkJWKS: true,
		},
		Registration: config.RegistrationConfig{Verification: iam.RegistrationVerificationNone},
		TwoFactor:    config.TwoFactorConfig{TOTPSecretKey: testTOTPKey},
	}
}

// maintenanceConfig is a verify-only engine without 2FA, for store, River and
// lifecycle tests.
func maintenanceConfig() config.Config {
	return config.Config{
		Keys:      config.KeysConfig{VerifyOnly: true},
		Token:     config.TokenConfig{Issuer: "https://maintenance.test", IssuedAudiences: []string{"test"}},
		TwoFactor: config.TwoFactorConfig{Mode: iam.TwoFactorDisabled},
	}
}

// newTestEngine is New on cfg and deps, closed at cleanup. A signing engine
// without a KeySource signs with testKeys.
func newTestEngine(t testing.TB, cfg config.Config, deps config.Deps) *Engine {
	t.Helper()
	if deps.KeySource == nil && !cfg.Keys.VerifyOnly {
		deps.KeySource = testKeys()
	}
	e, err := New(context.Background(), cfg, deps)
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	return e
}

var seq atomic.Int64

func uniqueSuffix() string { return fmt.Sprintf("%d%03d", time.Now().UnixNano(), seq.Add(1)) }

func uniqueEmail(prefix string) string { return prefix + "-" + uniqueSuffix() + "@example.com" }

func uniquePhone() string {
	s := uniqueSuffix()
	return "+1555" + s[len(s)-10:]
}

// testPassword is newUser's password.
const testPassword = "Correct-horse-battery-1"

// newUser creates an account with a verified email and testPassword.
func newUser(t *testing.T, e *Engine, prefix string) *db.User {
	t.Helper()
	ctx := t.Context()
	u, err := e.createUser(ctx, uniqueEmail(prefix), prefix+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, e.adminSetPassword(ctx, u.ID, testPassword))
	require.NoError(t, e.markEmailVerified(ctx, u.ID))
	return u
}

// markEmailVerified sets the flag without the proof transition.
func (s *Engine) markEmailVerified(ctx context.Context, id string) error {
	_, err := s.pg.Exec(ctx, `UPDATE users SET email_verified=true WHERE id=$1::uuid`, id)
	return err
}

func (s *Engine) adminSetPassword(ctx context.Context, id, pw string) error {
	_, err := s.UpdateUser(ctx, iam.SystemIdentity(), id, iam.UserUpdate{Password: &pw})
	return err
}

func (s *Engine) softDelete(ctx context.Context, id string) error {
	return itemErr(s.DeleteUsers(ctx, iam.SystemIdentity(), []string{id}))
}

// enableFactor enrolls a second factor without its proof ceremony; an email
// factor pins the account's current address.
func (s *Engine) enableFactor(ctx context.Context, userID, method string, phone *string, mode authflow.FactorEnrollmentMode) ([]string, error) {
	var email *string
	_ = s.pg.QueryRow(ctx, `SELECT email::text FROM users WHERE id=$1::uuid`, userID).Scan(&email)
	enabled, err := s.enable2FA(ctx, factorEnable{UserID: userID, Method: method, Phone: phone, Email: email, Mode: mode})
	return enabled.BackupCodes, err
}

// issueRefreshSession creates a password session and returns its refresh token.
func (s *Engine) issueRefreshSession(ctx context.Context, userID string) (sessionID, refreshToken string, err error) {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if _, err := s.lockLoginAccount(ctx, q, userID, 0); err != nil {
		return "", "", err
	}
	amr := []string{"pwd"}
	settings, settingsErr := s.get2FASettings(ctx, q, userID)
	status, statusErr := s.mfaStatusWith(settings, settingsErr)
	if err := s.requireSessionMFAStateOn(ctx, tx, userID, amr, status, statusErr); err != nil {
		return "", "", err
	}
	sid, rt, _, evicted, err := s.insertRefreshSessionTx(ctx, q, userID, "test", nil, amr)
	if err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	s.logSessionEvictions(ctx, userID, evicted)
	return sid, rt, nil
}

// expireDeletion deletes the account and moves its recovery window into the
// past, returning the deletion's generation. Nothing public shortens the
// window, so the test moves the stored times.
func expireDeletion(t *testing.T, s *Engine, userID string) string {
	t.Helper()
	require.NoError(t, s.softDelete(t.Context(), userID))
	_, err := s.pg.Exec(t.Context(), "UPDATE users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", userID)
	require.NoError(t, err)
	var generation string
	require.NoError(t, s.pg.QueryRow(t.Context(), `UPDATE account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours'
 FROM users u WHERE d.user_id=$1::uuid AND d.state='deleted' AND u.id=d.user_id RETURNING d.id::text`, userID).Scan(&generation))
	return generation
}

// prepareExpiredDeletion expires the account's deletion, finalizes it and
// delivers its purge callbacks, returning the deletion's generation.
func prepareExpiredDeletion(t *testing.T, s *Engine, userID string) string {
	t.Helper()
	generation := expireDeletion(t, s, userID)
	require.NoError(t, s.finalizeAccountDeletion(t.Context(), generation, false))
	rows, err := s.pg.Query(t.Context(), "SELECT id FROM account_deletion_deliveries WHERE deletion_id=$1::uuid AND completed_at IS NULL ORDER BY id", generation)
	require.NoError(t, err)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	for _, id := range ids {
		require.NoError(t, s.deliverAccountEvent(t.Context(), id))
	}
	return generation
}

// deliverEvents delivers the pending events of s's issuer through its OnEvent,
// oldest first, and returns their kinds.
func deliverEvents(t *testing.T, s *Engine) []iam.EventKind {
	t.Helper()
	rows, err := s.pg.Query(t.Context(), "SELECT id FROM account_events WHERE issuer=$1 ORDER BY id", s.cfg.Token.Issuer)
	require.NoError(t, err)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	var kinds []iam.EventKind
	for _, id := range ids {
		rec, err := s.q.AccountEventByID(t.Context(), id)
		require.NoError(t, err)
		kinds = append(kinds, iam.EventKind(rec.Kind))
		require.NoError(t, s.deliverEvent(t.Context(), id))
	}
	return kinds
}

// seedGroup creates a group as the host does, owned by the user ownerID ("" =
// no owner), and returns its id.
func seedGroup(ctx context.Context, e *Engine, persona iam.Persona, ownerID string) (string, error) {
	ng := iam.NewGroup{Persona: persona}
	if ownerID != "" {
		owner := iam.UserSubject(ownerID)
		ng.Owner = &owner
	}
	g, err := e.CreateGroup(ctx, ng)
	return g.ID, err
}

// mustRole is the role `<persona>:<name>`.
func mustRole(text string) iam.Role {
	var r iam.Role
	if err := r.UnmarshalText([]byte(text)); err != nil {
		panic(err)
	}
	return r
}

// itemErr is the outcome of a single-item batch call.
func itemErr(res []iam.OpResult, err error) error {
	if err != nil {
		return err
	}
	return res[0].Err
}

// roleIn is the role name of ref's persona.
func roleIn(ctx context.Context, e *Engine, ref iam.GroupRef, name string) (iam.Role, error) {
	group, err := e.Group(ctx, ref)
	return ident.Role(group.Persona, name), err
}

func assignRole(ctx context.Context, e *Engine, a auth.Identity, ref iam.GroupRef, subject iam.Subject, name string) error {
	role, err := roleIn(ctx, e, ref, name)
	if err != nil {
		return err
	}
	_, err = e.SetGroupRole(ctx, a, ref, subject, role)
	return err
}

func unassignRole(ctx context.Context, e *Engine, a auth.Identity, ref iam.GroupRef, subject iam.Subject, name string) error {
	role, err := roleIn(ctx, e, ref, name)
	if err != nil {
		return err
	}
	return e.RemoveGroupMember(ctx, a, ref, subject, ops.IfRole(role))
}

func removeMember(ctx context.Context, e *Engine, a auth.Identity, ref iam.GroupRef, subject iam.Subject) error {
	return e.RemoveGroupMember(ctx, a, ref, subject)
}

// grantRole assigns the role name of ref's persona with system authority.
func grantRole(t testing.TB, e *Engine, ref iam.GroupRef, subject iam.Subject, name string) {
	t.Helper()
	require.NoError(t, assignRole(t.Context(), e, iam.SystemIdentity(), ref, subject, name))
}

// failEphemeral makes event (INSERT OR UPDATE on NEW rows, DELETE on OLD) on
// ephemeral keys starting with prefix fail in PostgreSQL until restore runs.
func failEphemeral(t *testing.T, pool *pgxpool.Pool, event, row, prefix string) (restore func()) {
	t.Helper()
	name := "ephemeral_failure_" + uniqueSuffix()
	_, err := pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ephemeral failure'; END $$;
CREATE TRIGGER %[1]s BEFORE %[2]s ON ephemeral_kv FOR EACH ROW WHEN (%[3]s.key LIKE '%[4]s%%') EXECUTE FUNCTION %[1]s()`, name, event, row, prefix))
	require.NoError(t, err)
	var once sync.Once
	restore = func() {
		once.Do(func() {
			_, err := pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER %[1]s ON ephemeral_kv; DROP FUNCTION %[1]s()`, name))
			require.NoError(t, err)
		})
	}
	t.Cleanup(restore)
	return restore
}

// sentCode is the code of o's newest kind message; the test fails without one.
func sentCode(t *testing.T, o *testoutbox.Outbox, kind iam.MessageKind) string {
	t.Helper()
	code := o.Last(t, kind, "").Code
	require.NotEmpty(t, code)
	return code
}

// accountFlow is an engine behind its mounted HTTP surface on a real server,
// for tests that race a request against the engine's own locks. Delivery is
// the only substituted boundary.
type accountFlow struct {
	t          *testing.T
	engine     *Engine
	server     *httptest.Server
	email, sms *testoutbox.Outbox
}

type flowResponse struct {
	status  int
	raw     string
	header  http.Header
	cookies []*http.Cookie
	httpapi.AuthResult
	Secret string `json:"secret"`
	Error  struct {
		Code string `json:"code"`
	} `json:"error"`
}

// tokens is the answer's session; empty when it has none.
func (r flowResponse) tokens() iam.TokenSet {
	if r.TokenSet == nil {
		return iam.TokenSet{}
	}
	return *r.TokenSet
}

// challenge is a second_factor_required answer's challenge.
func (r flowResponse) challenge(t *testing.T) string {
	t.Helper()
	require.Equal(t, httpapi.AuthSecondFactorRequired, r.Status, r.raw)
	return r.SecondFactor.Challenge
}

// newAccountFlow serves an engine built from cfg and deps (Postgres is pool;
// Email and SMS are the flow's outboxes) with app links and TOTP enabled.
func newAccountFlow(t *testing.T, pool *pgxpool.Pool, cfg config.Config, deps config.Deps) *accountFlow {
	t.Helper()
	f := &accountFlow{t: t, email: &testoutbox.Outbox{}, sms: &testoutbox.Outbox{}}
	cfg.Frontend.BaseURL = "https://app.example"
	cfg.Frontend.VerifyPath, cfg.Frontend.PasswordlessPath, cfg.Frontend.PasswordResetPath = "/verify", "/login/link", "/reset"
	cfg.TwoFactor.TOTPSecretKey = testTOTPKey
	// The real limiter stays installed, loose enough for long setups;
	// apitest's TestWorkflowRateLimits proves its boundaries.
	limits := httpapi.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = ratelimit.Limit{Limit: 10000, Window: time.Minute}
	}
	cfg.HTTP = &config.HTTPConfig{DirectPeerIP: true, RateLimits: limits}
	deps.Postgres, deps.Email, deps.SMS = pool, f.email.Email(), f.sms.SMS()
	f.engine = newTestEngine(t, cfg, deps)
	service, err := httpapi.New(f.engine, f.engine.Config(), deps)
	require.NoError(t, err)
	t.Cleanup(service.Close)
	mounted, err := httpapi.NewMount(service)
	require.NoError(t, err)
	f.server = httptest.NewServer(mounted)
	f.server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(f.server.Close)
	return f
}

// do sends a JSON request to path under the API prefix, or from the root when
// path starts with "//".
func (f *accountFlow) do(method, path, token string, body any, header http.Header) flowResponse {
	f.t.Helper()
	data, err := json.Marshal(body)
	require.NoError(f.t, err)
	target := f.server.URL + config.DefaultAPIPath + config.APIVersion + path
	if rooted, ok := strings.CutPrefix(path, "//"); ok {
		target = f.server.URL + "/" + rooted
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(data))
	require.NoError(f.t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := f.server.Client().Do(req)
	require.NoError(f.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(f.t, err)
	out := flowResponse{status: resp.StatusCode, raw: string(raw), header: resp.Header, cookies: resp.Cookies()}
	if len(raw) > 0 && resp.Header.Get("Content-Type") == "application/json" {
		require.NoError(f.t, json.Unmarshal(raw, &out), string(raw))
	}
	return out
}

func (f *accountFlow) request(method, path, token string, body any) flowResponse {
	f.t.Helper()
	return f.do(method, path, token, body, nil)
}

func (f *accountFlow) post(path string, body any) flowResponse {
	f.t.Helper()
	return f.do(http.MethodPost, path, "", body, nil)
}

func (f *accountFlow) expect(status int, r flowResponse) flowResponse {
	f.t.Helper()
	require.Equal(f.t, status, r.status, r.raw)
	return r
}

// session asserts tokens are a live session established by amr.
func (f *accountFlow) session(tokens iam.TokenSet, amr ...string) {
	f.t.Helper()
	require.NotEmpty(f.t, tokens.RefreshToken)
	require.Greater(f.t, tokens.ExpiresIn, int64(0))
	claims, err := f.engine.Verify(context.Background(), tokens.AccessToken)
	require.NoError(f.t, err)
	require.NotEmpty(f.t, claims.UserID)
	require.ElementsMatch(f.t, amr, claims.AMR)
	f.expect(200, f.request("GET", "/me", tokens.AccessToken, nil))
}

// providerSignIn signs id in at idp's provider name as a page does: a JSON
// start carrying invite, the IdP's redirect back, and the JSON callback.
func (f *accountFlow) providerSignIn(idp *testidp.IdP, name string, id testidp.Identity, invite string) flowResponse {
	t := f.t
	t.Helper()
	start := f.do(http.MethodPost, "/oidc/"+name+"/login/start", "", map[string]string{"invite_code": invite}, nil)
	f.expect(200, start)
	var begun struct {
		AuthURL string `json:"auth_url"`
	}
	require.NoError(t, json.Unmarshal([]byte(start.raw), &begun))
	query := idp.Redirect(t, begun.AuthURL, id)
	query.Set("format", "json")
	cookies := http.Header{}
	for _, c := range start.cookies {
		cookies.Add("Cookie", c.Name+"="+c.Value)
	}
	callback := f.do(http.MethodGet, "//oidc/"+name+"/callback?"+query.Encode(), "", nil, cookies)
	require.Equal(t, "no-store", callback.header.Get("Cache-Control"))
	return callback
}

// completeWhileRevoking proves the revocation waits for an in-flight session
// completion, then returns its HTTP result for the scenario's token assertions.
// The caller must also check the intended final state: source-only revocation
// permits this already-authorized session; revoke-all must revoke it as well.
func (f *accountFlow) completeWhileRevoking(userID string, complete func() flowResponse, revoke func(context.Context) error) flowResponse {
	t := f.t
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// An independent control connection avoids occupying the application pool,
	// including CI's four-connection pool. It owns both the gate and observation.
	control, err := pgx.ConnectConfig(ctx, f.engine.pg.Config().ConnConfig.Copy())
	require.NoError(t, err)
	defer control.Close(context.Background())
	var pid int32
	require.NoError(t, control.QueryRow(ctx, `SELECT pg_backend_pid(), $1::uuid::text`, userID).Scan(&pid, &userID))
	const gateNamespace = 7363189
	name := fmt.Sprintf("flow_session_gate_%d", pid)
	function := pgx.Identifier{"profiles", name}.Sanitize()
	trigger := pgx.Identifier{name}.Sanitize()
	gateHeld := false
	// Always release the gate before dropping its DDL, including assertion
	// failures; otherwise an INSERT can retain a table lock and stall cleanup.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if gateHeld {
			_, unlockErr := control.Exec(cleanup, `SELECT pg_advisory_unlock($1::int, $2::int)`, gateNamespace, pid)
			if unlockErr != nil {
				t.Errorf("release session gate: %v", unlockErr)
			}
		}
		_, dropErr := control.Exec(cleanup, "DROP TRIGGER IF EXISTS "+trigger+" ON refresh_sessions; DROP FUNCTION IF EXISTS "+function+"()")
		if dropErr != nil {
			t.Errorf("remove session gate: %v", dropErr)
		}
	}()
	_, err = control.Exec(ctx, "CREATE FUNCTION "+function+`() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.user_id::text = TG_ARGV[0] THEN
    PERFORM pg_advisory_xact_lock(7363189, TG_ARGV[1]::int);
  END IF;
  RETURN NEW;
END $$`)
	require.NoError(t, err)
	// userID was canonicalized by PostgreSQL above; only this account is paused.
	_, err = control.Exec(ctx, fmt.Sprintf("CREATE TRIGGER %s BEFORE INSERT ON refresh_sessions FOR EACH ROW EXECUTE FUNCTION %s('%s', '%d')", trigger, function, userID, pid))
	require.NoError(t, err)
	_, err = control.Exec(ctx, `SELECT pg_advisory_lock($1::int, $2::int)`, gateNamespace, pid)
	require.NoError(t, err)
	gateHeld = true

	completed := make(chan flowResponse, 1)
	go func() {
		defer close(completed)
		completed <- complete()
	}()
	var revoked chan error
	// Observe actual lock ownership, not query text (which depends on DB-role
	// visibility). All assertions stay on the test goroutine. Early completion
	// fails immediately instead of being mistaken for a scheduling delay.
	waitForBackend := func(stage, query string, args ...any) int32 {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var backend int32
			require.NoError(t, control.QueryRow(ctx, query, args...).Scan(&backend), stage)
			if backend != 0 {
				return backend
			}
			select {
			case response, ok := <-completed:
				t.Fatalf("%s: completion returned before gate release (response=%t, status=%d, body=%s)", stage, ok, response.status, response.raw)
			case revokeErr, ok := <-revoked:
				t.Fatalf("%s: revocation did not wait for completion (result=%t, error=%v)", stage, ok, revokeErr)
			case <-ctx.Done():
				t.Fatalf("%s: %v", stage, ctx.Err())
			case <-ticker.C:
			}
		}
	}
	insertPID := waitForBackend("session INSERT waiting on gate", `SELECT COALESCE((
  SELECT pid FROM pg_locks WHERE locktype='advisory' AND NOT granted
  AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND classid=$1::oid AND objid=$2::oid AND objsubid=2 LIMIT 1
), 0)`, gateNamespace, pid)
	revoked = make(chan error, 1)
	go func() {
		defer close(revoked)
		revoked <- revoke(ctx)
	}()
	waitForBackend("revocation waiting on completion", `SELECT COALESCE((
  SELECT pid FROM pg_locks WHERE NOT granted AND $1::int=ANY(pg_blocking_pids(pid)) LIMIT 1
), 0)`, insertPID)
	var unlocked bool
	require.NoError(t, control.QueryRow(ctx, `SELECT pg_advisory_unlock($1::int, $2::int)`, gateNamespace, pid).Scan(&unlocked))
	require.True(t, unlocked)
	gateHeld = false
	var response flowResponse
	select {
	case result, ok := <-completed:
		require.True(t, ok, "completion exited without an HTTP response")
		response = result
	case <-ctx.Done():
		t.Fatalf("session completion after gate release: %v", ctx.Err())
	}
	select {
	case revokeErr, ok := <-revoked:
		require.True(t, ok, "revocation exited without a result")
		require.NoError(t, revokeErr)
	case <-ctx.Done():
		t.Fatalf("revocation after gate release: %v", ctx.Err())
	}
	return response
}
