package authhttp

// Shared fixtures for the retained public workflows and focused security checks.
import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/password"
	"github.com/open-rails/authkit/verify"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

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
	control, err := pgx.ConnectConfig(ctx, f.service.svc.Postgres().Config().ConnConfig.Copy())
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

func createAccountInvite(t *testing.T, srv *Service, pool *pgxpool.Pool, email string) (string, authkit.AccountRegistrationInviteCreated) {
	t.Helper()
	ctx := context.Background()
	_, err := srv.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	inviter, err := srv.svc.CreateUser(ctx, uniqueEmail("account-inviter"), "accountinviter"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(inviter.ID), authkit.OwnerRole))
	invite, err := srv.svc.CreateAccountRegistrationInvite(ctx, authkit.CreateAccountRegistrationInviteRequest{
		Email:     email,
		InvitedBy: inviter.ID,
	})
	require.NoError(t, err)
	return inviter.ID, invite
}

func requireAccountInviteConsumed(t *testing.T, pool *pgxpool.Pool, inviteID, userID string) {
	t.Helper()
	var consumed bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT consumed_at IS NOT NULL AND consumed_by = $2::uuid
		   FROM account_registration_invites WHERE id = $1::uuid`,
		inviteID, userID).Scan(&consumed))
	require.True(t, consumed)
}

func adminTestPublicKeyPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func serveAuthJSON(srv *Service, method, path, body, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	srv.apiHandler().ServeHTTP(w, r)
	return w
}

func testTOTPCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	require.NoError(t, err)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1000000)
}

// delegateCertificate is a self-signed client leaf a test presents over mTLS.
type delegateCertificate struct {
	Leaf *x509.Certificate
	TLS  tls.Certificate
}

func (c delegateCertificate) encoded() string {
	return base64.RawURLEncoding.EncodeToString(c.Leaf.Raw)
}

func newDelegateCertificate(t *testing.T, mutate func(*x509.Certificate)) delegateCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "delegate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return delegateCertificate{Leaf: leaf, TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}
}

// oversizedExtension pushes a certificate past maxDelegateCertificateDER
// while keeping it parseable.
func oversizedExtension() pkix.Extension {
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, maxDelegateCertificateDER)}
}

// newDelegatedVerifier builds a Verifier trusting a single remote application.
func newDelegatedVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) *verify.Verifier {
	t.Helper()
	v := verify.NewVerifier()

	if err := v.AddIssuer(iss, aud, verify.IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatalf("AddIssuer: %v", err)
	}
	return v
}

// Test-only embedded.Deps builders so a call site names only what it wires.
type coreOpt func(*embedded.Deps)

func withPostgres(pool *pgxpool.Pool) coreOpt { return func(d *embedded.Deps) { d.Postgres = pool } }

func withRedis(rd *redis.Client) coreOpt { return func(d *embedded.Deps) { d.Redis = rd } }

func withEmailSender(s embedded.EmailSender) coreOpt { return func(d *embedded.Deps) { d.Email = s } }

func withSMSSender(s embedded.SMSSender) coreOpt { return func(d *embedded.Deps) { d.SMS = s } }

func withClock(now func() time.Time) coreOpt { return func(d *embedded.Deps) { d.Clock = now } }

func withSolanaSNSResolver(r embedded.SolanaSNSResolver) coreOpt {
	return func(d *embedded.Deps) { d.SolanaSNSResolver = r }
}

func withDelegatedAuthorization(a embedded.DelegationAuthorizer) coreOpt {
	return func(d *embedded.Deps) { d.DelegatedAuthorization = a }
}

func depsOf(opts ...coreOpt) embedded.Deps {
	var d embedded.Deps
	for _, o := range opts {
		if o != nil {
			o(&d)
		}
	}
	return d
}

// coreFromConfig is embedded.NewFromConfig with the pool positional and Deps
// composed from options.
// coreFromConfig is embedded.New with the pool positional and Deps composed
// from options. A test that wires neither Redis nor an EphemeralStore gets the
// memory store New defaults to, so the opt-in is implied (the host-facing
// refusal is pinned in embedded and by TestNewServer_RequiresClientIPPosture).
func coreFromConfig(cfg embedded.Config, pool *pgxpool.Pool, opts ...coreOpt) (*embedded.Runtime, error) {
	deps := depsOf(append([]coreOpt{withPostgres(pool)}, opts...)...)
	if deps.Redis == nil && deps.EphemeralStore == nil {
		cfg.Ephemeral.AllowMemory = true
	}
	return embedded.New(cfg, deps)
}

const documentsTestType = "example.entitlements/v1"

// registerDocumentReader registers a remote application (static keys) nested
// under the root group and returns a bearer token minted by ITS OWN key.
func registerDocumentReader(t *testing.T, core *embedded.Runtime, slug, issuer string) string {
	t.Helper()
	ctx := context.Background()
	coreSvc := core
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	rootGID, err := coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	_, err = coreSvc.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              slug,
		PermissionGroupID: rootGID,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys: []authkit.RemoteAppKey{{
			KID:          signer.KID(),
			PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey()),
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = coreSvc.DeleteRemoteApplication(context.Background(), issuer) })

	// A remote application addresses its token to THIS platform (ak#324: the
	// lazily-loaded issuer enforces Config.Token.ExpectedAudiences).
	token, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{
		Issuer:    issuer,
		Audiences: []string{"test-app"},
		TTL:       time.Minute,
	})
	require.NoError(t, err)
	return token
}

func getDocument(h http.Handler, method, digest, token string, header http.Header) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, documents.PublicationPathPrefix+digest, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for key, values := range header {
		for _, value := range values {
			r.Header.Set(key, value)
		}
	}
	h.ServeHTTP(w, r)
	return w
}

// nestedTokenBody decodes a composite response ({"token_set": ...}) into the
// flat token fields older assertions read.
type nestedTokenBody struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
}

func (b *nestedTokenBody) UnmarshalJSON(raw []byte) error {
	var env struct {
		TokenSet authkit.TokenSet `json:"token_set"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	b.AccessToken, b.TokenType, b.ExpiresIn = env.TokenSet.AccessToken, env.TokenSet.TokenType, env.TokenSet.ExpiresIn
	return nil
}

// requireErrorCode decodes the Stripe-style error envelope (#115) and asserts
// the machine-readable code, plus that type and message are always populated.
// Replaces the old flat `{"error":"<code>"}` JSONEq assertions.
func requireErrorCode(t *testing.T, body, code string) {
	t.Helper()
	var env authkit.ErrorEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &env), "error body: %s", body)
	require.Equal(t, code, env.Error.Code, "error body: %s", body)
	require.NotEmpty(t, env.Error.Type, "error.type must be set")
	require.NotEmpty(t, env.Error.Message, "error.message must be set")
}

// Focused handler regressions use the same public mount as a host. The account
// journeys use its default API prefix; these existing request helpers use root.
func (s *Service) apiHandler() http.Handler {
	mounted, err := MountHandler(s, MountOptions{APIPrefix: "/"})
	if err != nil {
		panic(err)
	}
	return mounted
}

func (s *Service) oidcHandler() http.Handler {
	return s.apiHandler()
}

// echoClaimsHandler is the protected resource: it reports the claims the gate
// handed downstream, which is how the freshness assertion is made against a real
// response body rather than an in-process value.
func echoClaimsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, err := verify.GetClaims(r.Context())
		if err != nil {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s|%s|%t", cl.UserID, cl.Username, cl.EmailVerified)
	})
}

func mustPasswordUser(t *testing.T, srv *Service, prefix string) string {
	t.Helper()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := srv.svc.CreateUser(context.Background(), email, username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.svc.Postgres().Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id("Correct-password-12345")
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(context.Background(), user.ID, hash, "argon2id"))
	return user.ID
}

func testPasskeyFullCeremonyAndAssurance(t *testing.T, store ephemeralStore) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Passkeys = embedded.PasskeyConfig{
		RPID:             "example.com",
		RPDisplayName:    "Example",
		Origins:          []string{"https://example.com"},
		UserVerification: "preferred",
	}
	srv, err := newServer(newServerClient(t, cfg, pool, store.engineOpts()...), WithoutRateLimiter())
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("passkey-full"), "passkeyfull"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, user.ID) })

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	authn := passkeytest.New(t, "https://example.com")

	w := serveAuthJSON(srv, http.MethodPost, "/passkeys/register/begin", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var creation passkeyCreationOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	require.Equal(t, "Example", creation.PublicKey.RP.Name)
	require.Equal(t, "example.com", creation.PublicKey.RP.ID)
	require.Equal(t, "required", creation.PublicKey.AuthenticatorSelection.ResidentKey)
	require.Empty(t, creation.PublicKey.ExcludeCredentials)

	w = serveAuthJSON(srv, http.MethodPost, "/passkeys/register/finish", string(attest(t, authn, creation)), setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var created embedded.Passkey
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.True(t, created.BackupEligible)
	require.True(t, created.BackupState)

	w = serveAuthJSON(srv, http.MethodPost, "/passkeys/register/begin", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	require.Len(t, creation.PublicKey.ExcludeCredentials, 1)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(authn.CredentialID), creation.PublicKey.ExcludeCredentials[0].ID)

	for _, body := range []string{`{"identifier":"does-not-exist@example.com"}`, `{"identifier":"` + *user.Email + `"}`, `{"`, `[]`, `null`} {
		w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", body)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var assertion passkeyRequestOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	require.Empty(t, assertion.PublicKey.AllowCredentials)

	firstAssertion := string(assert(t, authn, assertion, 1))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", firstAssertion)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.Equal(t, embedded.AssuranceLevelMFA, claims["acr"])
	require.ElementsMatch(t, []any{"swk", "mfa"}, claims["amr"])
	require.NotZero(t, claims["auth_time"])

	// #288/9: the identical assertion replayed — the ceremony was consumed on
	// the first finish, so the replay must be rejected.
	replay := serveJSON(srv, http.MethodPost, "/passkeys/login/finish", firstAssertion)
	require.Equal(t, http.StatusUnauthorized, replay.Code, replay.Body.String())

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	require.Empty(t, assertion.PublicKey.AllowCredentials)
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(assert(t, authn, assertion, 2)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(assert(t, authn, assertion, 2)))
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_credentials")

	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []embedded.Passkey `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	require.NotNil(t, listed.Data[0].LastUsedAt)
	require.Equal(t, created.ID, listed.Data[0].ID)
	// Management uses the credential established by the actual ceremony.
	for _, label := range []string{"old", "new"} {
		w = serveAuthJSON(srv, http.MethodPatch, "/passkeys/"+created.ID, `{"label":"`+label+`"}`, setupToken)
		require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
		w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, setupToken)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
		require.NotNil(t, listed.Data[0].Label)
		require.Equal(t, label, *listed.Data[0].Label)
	}
	w = serveAuthJSON(srv, http.MethodDelete, "/passkeys/"+created.ID, `{}`, setupToken)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Empty(t, listed.Data)
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(assert(t, authn, assertion, 3)))
	require.Equal(t, http.StatusUnauthorized, w.Code, "deleted credentials cannot log in: %s", w.Body.String())
}

// The wire shapes the browser sees, decoded only as far as the tests assert on them.
type passkeyCreationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			ResidentKey string `json:"residentKey"`
		} `json:"authenticatorSelection"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type passkeyRequestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func attest(t *testing.T, authn *passkeytest.Authenticator, opts passkeyCreationOptions) []byte {
	t.Helper()
	return authn.Attestation(t, opts.PublicKey.RP.ID, passkeytest.UserHandle(t, opts.PublicKey.User.ID), opts.PublicKey.Challenge)
}

func assert(t *testing.T, authn *passkeytest.Authenticator, opts passkeyRequestOptions, signCount uint32) []byte {
	t.Helper()
	return authn.Assertion(t, opts.PublicKey.RPID, opts.PublicKey.Challenge, signCount)
}

var resetVerifySeq atomic.Int64

type captureEmailSender struct {
	mu            sync.Mutex
	loginCode     string
	inviteURL     string
	resetToken    string
	resetURL      string
	verifyCode    string
	verifyToken   string
	verifyURL     string
	deviceNotices []string
}

func (s *captureEmailSender) SendDeviceKeyEnrolled(_ context.Context, email, _ string, _ embedded.DeviceKeyNotice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceNotices = append(s.deviceNotices, email)
	return nil
}

func (s *captureEmailSender) deviceKeyNotices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deviceNotices...)
}

func (s *captureEmailSender) SendVerification(_ context.Context, _, _ string, msg embedded.VerificationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCode = msg.Code
	s.verifyURL = msg.LinkURL
	s.verifyToken = tokenFromURL(msg.LinkURL)
	return nil
}

func (s *captureEmailSender) SendPasswordResetLink(_ context.Context, _, _, resetURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetURL = resetURL
	s.resetToken = tokenFromURL(resetURL)
	return nil
}

func (s *captureEmailSender) SendAccountRegistrationInvite(_ context.Context, _ string, link string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inviteURL = link
	return nil
}

func (s *captureEmailSender) lastInviteURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inviteURL
}

func (s *captureEmailSender) SendLoginCode(_ context.Context, _, _ string, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginCode = code
	return nil
}

func (s *captureEmailSender) lastLoginCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginCode
}

func (s *captureEmailSender) SendWelcome(context.Context, string, string) error { return nil }

func (s *captureEmailSender) SendContactChanged(context.Context, string, string, embedded.ContactChange) error {
	return nil
}

func (s *captureEmailSender) passwordResetToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.resetToken)
	return s.resetToken
}

func (s *captureEmailSender) verificationCode(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyCode)
	return s.verifyCode
}

func (s *captureEmailSender) verificationToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyToken)
	return s.verifyToken
}

func (s *captureEmailSender) verificationURL(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyURL)
	return s.verifyURL
}

type captureSMSSender struct {
	mu          sync.Mutex
	loginCode   string
	resetToken  string
	resetURL    string
	verifyCode  string
	verifyToken string
	verifyURL   string
}

func (s *captureSMSSender) SendVerification(_ context.Context, _ string, msg embedded.VerificationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCode = msg.Code
	s.verifyURL = msg.LinkURL
	s.verifyToken = tokenFromURL(msg.LinkURL)
	return nil
}

func (s *captureSMSSender) SendPasswordResetLink(_ context.Context, _ string, resetURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetURL = resetURL
	s.resetToken = tokenFromURL(resetURL)
	return nil
}

func (s *captureSMSSender) SendLoginCode(_ context.Context, _ string, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginCode = code
	return nil
}

func (s *captureSMSSender) lastLoginCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginCode
}

func (s *captureSMSSender) SendContactChanged(context.Context, string, embedded.ContactChange) error {
	return nil
}

func (s *captureSMSSender) verificationCode(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyCode)
	return s.verifyCode
}

func tokenFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	fragment, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(fragment.Get("token"))
}

func serveJSON(srv *Service, method, path, body string) *httptest.ResponseRecorder {
	return serveRequest(srv, method, path, body)
}

func serveRequest(srv *Service, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.apiHandler().ServeHTTP(w, r)
	return w
}

func uniqueEmail(prefix string) string {
	return prefix + "-" + uniqueSuffix() + "@example.com"
}

func uniquePhone() string {
	suffix := uniqueSuffix()
	if len(suffix) > 10 {
		suffix = suffix[len(suffix)-10:]
	}
	return "+1555" + suffix
}

func uniqueSuffix() string {
	n := resetVerifySeq.Add(1)
	return fmt.Sprintf("%d%03d", time.Now().UnixNano(), n)
}

func passwordlessTestServer(t *testing.T, autoRegister bool) (*Service, *captureEmailSender, *captureSMSSender) {
	t.Helper()
	pool := testdb.Pool(t)
	cfg := newServerTestConfig()
	cfg.Frontend.PasswordlessPath = "/wallet/login"
	cfg.Registration.PasswordlessLogin = true
	cfg.Registration.PasswordlessAutoRegistration = autoRegister
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(emailSender), withSMSSender(smsSender)), WithoutRateLimiter())
	require.NoError(t, err)
	return srv, emailSender, smsSender
}

// drive runs one generated route handler at a concrete (no sub-resource) path,
// with the caller's claims set, and returns the recorder. Sub-resource DELETEs
// (:key / :app / :invite) are driven inline via driveSub.
func (s *Service) drive(t *testing.T, gr embedded.GeneratedRoute, instanceSlug, caller, body string) *httptest.ResponseRecorder {
	t.Helper()
	path := strings.ReplaceAll(gr.Path, ":instance_slug", instanceSlug)
	r := httptest.NewRequest(gr.Method, "http://x"+path, strings.NewReader(body))
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.generatedGroupHandler(gr).ServeHTTP(w, r)
	return w
}

// driveSub runs a sub-resource handler (DELETE with :key/:app/:invite) at a
// concrete path, with claims set.
func (s *Service) driveSub(t *testing.T, gr embedded.GeneratedRoute, repl *strings.Replacer, caller string) *httptest.ResponseRecorder {
	t.Helper()
	path := repl.Replace(gr.Path)
	r := httptest.NewRequest(gr.Method, "http://x"+path, nil)
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.generatedGroupHandler(gr).ServeHTTP(w, r)
	return w
}

// withMuxParams rebuilds the request through a one-route ServeMux so r.PathValue
// is populated exactly as it would be in production (PathValue is only set when a
// request is matched by a pattern; httptest.NewRequest alone does not set it).
func withMuxParams(r *http.Request, colonPath string, _ map[string]string) *http.Request {
	pattern := r.Method + " " + muxPath(colonPath)
	mux := http.NewServeMux()
	var matched *http.Request
	mux.HandleFunc(pattern, func(_ http.ResponseWriter, rr *http.Request) { matched = rr })
	mux.ServeHTTP(httptest.NewRecorder(), r)
	if matched != nil {
		// Preserve the caller-set context (claims/body) on the matched request.
		return matched
	}
	return r
}

// instanceCreateTestConfig declares an "org" persona with generated creation
// enabled: a slug pattern tighter than the built-in rule (no dots), one
// reserved slug escalated to the root "site-admin" role, and remote
// applications on for the role-assignment route.
func instanceCreateTestConfig() embedded.Config {
	cfg := newServerTestConfig()
	cfg.RBAC = []embedded.PersonaDef{
		{Name: authkit.RootPersona, Roles: []embedded.RoleDef{
			{Name: "site-admin", Permissions: []string{"root:resources:read"}},
		}},
		{
			Name:         "org",
			Parent:       authkit.RootPersona,
			Capabilities: embedded.PersonaCapabilities{RemoteApplications: true},
			Roles: []embedded.RoleDef{
				{Name: "member", Permissions: []string{"org:catalog:read"}},
				{Name: "credential-manager", Permissions: []string{"org:credentials:manage", "org:credentials:read"}},
			},
			Creation: embedded.InstanceCreationDef{
				Enabled:                true,
				SlugPattern:            `[a-z0-9][a-z0-9-]{0,30}`,
				ReservedSlugs:          []string{"platform"},
				ReservedEscalationRole: "site-admin",
			},
		},
	}
	return cfg
}

func newInstanceTestUser(t *testing.T, srv *Service, prefix string) (id, token string) {
	t.Helper()
	ctx := context.Background()
	user, err := srv.svc.CreateUser(ctx, uniqueEmail(prefix), prefix+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, user.ID) })
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	tok, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, tok
}

func postOrg(srv *Service, token, body string) *httptest.ResponseRecorder {
	return serveAuthJSON(srv, http.MethodPost, "/org", body, token)
}

// testOAuth2Provider is an OAuth2 provider against a fake IdP rooted at base:
// /authorize, /token, and /me returning {id|sub, email, email_verified, login, name}.
func testOAuth2Provider(name, base, clientID, secret string, opts ...authprovider.Option) authprovider.Provider {
	return authprovider.OAuth2(name, base, authprovider.Endpoint{AuthorizeURL: base + "/authorize", TokenURL: base + "/token"},
		clientID, secret, testUserInfo(base+"/me"), opts...)
}

func testUserInfo(url string) authprovider.UserInfoFunc {
	return func(ctx context.Context, client *http.Client) (authprovider.Identity, error) {
		var me struct {
			ID       any    `json:"id"`
			Sub      string `json:"sub"`
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
			Login    string `json:"login"`
			Name     string `json:"name"`
		}
		if err := authprovider.GetJSON(ctx, client, url, "", &me); err != nil {
			return authprovider.Identity{}, err
		}
		subject := authprovider.IdentityID(me.ID)
		if subject == "" {
			subject = me.Sub
		}
		return authprovider.Identity{Subject: subject, Email: me.Email, EmailVerified: me.Verified, PreferredUsername: me.Login, DisplayName: me.Name}, nil
	}
}

// setTestProviders installs providers on a Service without validation (tests
// that point at http fake IdPs).
func setTestProviders(s *Service, providers ...authprovider.Provider) {
	s.providers = make(map[string]authprovider.Provider, len(providers))
	for _, p := range providers {
		s.providers[p.Name()] = p
	}
}

// newCookieTestUser creates a password user and returns its id + credentials.
func newCookieTestUser(t *testing.T, pool *pgxpool.Pool, srv *Service, prefix string) (email, pass string) {
	t.Helper()
	ctx := context.Background()
	email = uniqueEmail(prefix)
	pass = "correct-horse-battery-97"
	user, err := srv.svc.CreateUser(ctx, email, prefix+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id"))
	return email, pass
}

func stalePasswordUserToken(t *testing.T, srv *Service, pool *pgxpool.Pool, prefix, pass string) (string, string) {
	t.Helper()
	ctx := context.Background()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id"))
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE refresh_sessions SET last_authenticated_at=$1 WHERE id=$2::uuid`, time.Now().Add(-time.Hour), sid)
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, token
}

// Test-only Config builders: New takes one Config; tests compose it from these
// so a call site names only what it sets. newServer supplies the direct-peer
// posture unless the options declare one.
type Option func(*Config)

func WithoutRateLimiter() Option { return func(c *Config) { c.DisableRateLimiting = true } }

func WithDocuments(providers ...DocumentProvider) Option {
	return func(c *Config) { c.Documents = append(c.Documents, providers...) }
}

func configOf(opts ...Option) Config {
	var c Config
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	if c.ClientIP == nil && !c.DirectPeerIP && len(c.TrustedProxies) == 0 && len(c.CloudflareProxies) == 0 {
		c.DirectPeerIP = true
	}
	return c
}

func newServer(client *embedded.Runtime, opts ...Option) (*Service, error) {
	return New(client, configOf(opts...))
}

// testSigner is one RSA keypair shared by the package's test engines: explicit
// keys instead of AllowEphemeralDevKeys, which persists a keypair under the
// package directory.
var testSigner = sync.OnceValue(func() *jwtkit.RSASigner {
	s, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		panic(err)
	}
	return s
})

func testKeys() embedded.KeysConfig {
	s := testSigner()
	return embedded.KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}}
}

func newServerTestConfig() embedded.Config {
	return embedded.Config{
		Keys: testKeys(),
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
		DeviceKeys:   embedded.DeviceKeysConfig{Enabled: true},
		Ephemeral:    embedded.EphemeralConfig{AllowMemory: true},
		// The harness's IdPs and JWKS endpoints are loopback httptest servers.
		Applications: embedded.ApplicationsConfig{AllowPrivateNetworkJWKS: true},
	}
}

// newServerClient builds the embedded engine that a client-first NewServer wraps
// (#142). engineOpts are wired onto the client; HTTP-layer options stay on NewServer.
func newServerClient(t *testing.T, cfg embedded.Config, pool *pgxpool.Pool, engineOpts ...coreOpt) *embedded.Runtime {
	t.Helper()
	deps := depsOf(append([]coreOpt{withPostgres(pool)}, engineOpts...)...)
	if deps.Redis == nil && deps.EphemeralStore == nil {
		cfg.Ephemeral.AllowMemory = true // the harness's memory store is deliberate
	}
	c, err := embedded.New(cfg, deps)
	require.NoError(t, err)
	return c
}

type stepUpOptionsTestShape struct {
	Methods       []string `json:"methods"`
	DefaultMethod string   `json:"default_method"`
	Options       []struct {
		ID             string `json:"id"`
		Method         string `json:"method"`
		IsDefault      bool   `json:"is_default"`
		VerificationID string `json:"verification_id"`
	} `json:"options"`
}

func requireStepUp2FAOptions(t *testing.T, got stepUpOptionsTestShape, methods []string, defaultMethod string) {
	t.Helper()
	require.ElementsMatch(t, methods, got.Methods)
	require.Equal(t, defaultMethod, got.DefaultMethod)
	seen := map[string]bool{}
	for _, option := range got.Options {
		require.Empty(t, option.ID)
		require.NotEmpty(t, option.Method)
		seen[option.Method] = true
		if option.Method == defaultMethod {
			require.True(t, option.IsDefault)
		}
		if option.Method == "email" || option.Method == "sms" {
			require.NotEmpty(t, option.VerificationID)
		}
	}
	for _, method := range methods {
		require.True(t, seen[method], "missing 2FA option %q", method)
	}
}

// ephemeralStore is one leg of the store matrix: the in-memory ephemeral store
// (rdb nil) or a scratch Redis, the store production runs on.
type ephemeralStore struct {
	name string
	rdb  *redis.Client
}

// engineOpts wires the store onto embedded.New; NewServer then reuses the
// engine's Redis for its OIDC/SIWS caches and limiter (#210).
func (e ephemeralStore) engineOpts() []coreOpt {
	if e.rdb == nil {
		return nil
	}
	return []coreOpt{withRedis(e.rdb)}
}

// forEachStore runs fn under the memory store and under a scratch Redis
// (AUTHKIT_TEST_REDIS_URL; always set in CI, where the skip gate enforces it),
// so every single-use / replay pin is proven against the production store.
func forEachStore(t *testing.T, fn func(t *testing.T, store ephemeralStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { fn(t, ephemeralStore{name: "memory"}) })
	t.Run("redis", func(t *testing.T) { fn(t, ephemeralStore{name: "redis", rdb: testdb.ScratchRedis(t)}) })
}

func unverifiedAccessClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	assertWireGolden(t, "access-header", parsed.Header)
	return claims
}

// Goldens require the documented fields and types while allowing additive keys.
// They inspect actual HTTP/JWT output, independently of Go DTO field names.
func assertWireGolden(t *testing.T, name string, value any) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "wire", name+".json"))
	require.NoError(t, err)
	var expected, actual any
	require.NoError(t, json.Unmarshal(fixture, &expected))
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, &actual))
	var match func(any, any, string)
	match = func(want, got any, path string) {
		switch want := want.(type) {
		case map[string]any:
			require.IsType(t, want, got, path)
			fields := got.(map[string]any)
			for key, value := range want {
				require.Contains(t, fields, key, path)
				match(value, fields[key], path+"."+key)
			}
		case string:
			switch want {
			case "$string":
				require.IsType(t, "", got, path)
				require.NotEmpty(t, got, path)
			case "$text":
				require.IsType(t, "", got, path)
			case "$number":
				require.IsType(t, float64(0), got, path)
				require.Greater(t, got.(float64), float64(0), path)
			case "$strings":
				require.IsType(t, []any{}, got, path)
				require.NotEmpty(t, got, path)
				for _, item := range got.([]any) {
					match("$string", item, path+"[]")
				}
			default:
				require.Equal(t, want, got, path)
			}
		case []any:
			// A single object is an item schema; scalar arrays pin exact values.
			if len(want) == 1 {
				if _, object := want[0].(map[string]any); object {
					require.IsType(t, []any{}, got, path)
					require.NotEmpty(t, got, path)
					for _, item := range got.([]any) {
						match(want[0], item, path+"[]")
					}
					return
				}
			}
			require.Equal(t, want, got, path)
		default:
			require.Equal(t, want, got, path)
		}
	}
	match(expected, actual, name)
}
