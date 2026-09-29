package engine

// Shared fixtures for the retained public workflows and focused security checks.
import (
	"bytes"
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
	"io"

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
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
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
	control, err := pgx.ConnectConfig(ctx, fixtureBackend(f.service.Backend()).pg.Config().ConnConfig.Copy())
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

func createAccountInvite(t *testing.T, srv *httpapi.Service, pool *pgxpool.Pool, email string) (string, iam.AccountInviteCreated) {
	t.Helper()
	ctx := context.Background()
	_, err := fixtureBackend(srv.Backend()).ensureRootGroup(ctx)
	require.NoError(t, err)
	inviter, err := fixtureBackend(srv.Backend()).createUser(ctx, uniqueEmail("account-inviter"), "accountinviter"+uniqueSuffix())
	require.NoError(t, err)
	seedRole(t, fixtureBackend(srv.Backend()), iam.RootGroup(), iam.UserSubject(inviter.ID), "owner")
	invite, err := srv.Backend().CreateAccountInvite(ctx, iam.UserActor(inviter.ID), iam.NewAccountInvite{Email: email})
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

func serveAuthJSON(srv *httpapi.Service, method, path, body, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	apiHandler(srv).ServeHTTP(w, r)
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
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, httpapi.MaxDelegateCertificateDER)}
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

// Test-only authkit.Deps builders so a call site names only what it wires.
type coreOpt func(*Deps)

func withPostgres(pool *pgxpool.Pool) coreOpt { return func(d *Deps) { d.Postgres = pool } }

func withEmailSender(s EmailSender) coreOpt { return func(d *Deps) { d.Email = s } }

func withSMSSender(s SMSSender) coreOpt { return func(d *Deps) { d.SMS = s } }

func withClock(now func() time.Time) coreOpt { return func(d *Deps) { d.Clock = now } }

func withSolanaSNSResolver(r SolanaSNSResolver) coreOpt {
	return func(d *Deps) { d.SolanaSNSResolver = r }
}

func withDelegatedAuthorization(a iam.DelegationAuthorizer) coreOpt {
	return func(d *Deps) { d.DelegatedAuthorization = a }
}

func depsOf(opts ...coreOpt) Deps {
	var d Deps
	for _, o := range opts {
		if o != nil {
			o(&d)
		}
	}
	return d
}

// coreFromConfig is authkit.New with the pool positional and Deps composed
// from options; without Redis it runs on the default memory store.
func coreFromConfig(cfg Config, pool *pgxpool.Pool, opts ...coreOpt) (*Engine, error) {
	return New(context.Background(), cfg, depsOf(append([]coreOpt{withPostgres(pool)}, opts...)...))
}

// mintRemoteApplicationToken signs a remote-application access token with the
// application's own key: typ remote-application-access+jwt, no subject. A
// non-nil perms narrows the stored authority.
func mintRemoteApplicationToken(t *testing.T, signer jwtkit.Signer, issuer string, audiences, perms []string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{"iss": issuer, "aud": audiences, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	if perms != nil {
		claims["permissions"] = perms
	}
	token, err := jwtkit.SignWithType(context.Background(), signer, claims, jwtkit.RemoteApplicationAccessTokenType, true)
	require.NoError(t, err)
	return token
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
		TokenSet iam.TokenSet `json:"token_set"`
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
	var env iam.ErrorEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &env), "error body: %s", body)
	require.Equal(t, code, env.Error.Code, "error body: %s", body)
	require.NotEmpty(t, env.Error.Type, "error.type must be set")
	require.NotEmpty(t, env.Error.Message, "error.message must be set")
}

// Focused handler regressions use the same public mount as a host. The account
// journeys use its default API prefix; these existing request helpers use root.
func apiHandler(s *httpapi.Service) http.Handler {
	mounted, err := httpapi.NewMount(s, httpapi.MountOptions{APIPath: "/"})
	if err != nil {
		panic(err)
	}
	return mounted
}

func oidcHandler(s *httpapi.Service) http.Handler {
	return apiHandler(s)
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

func mustPasswordUser(t *testing.T, srv *httpapi.Service, prefix string) string {
	t.Helper()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := fixtureBackend(srv.Backend()).createUser(context.Background(), email, username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = fixtureBackend(srv.Backend()).pg.Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	require.NoError(t, fixtureBackend(srv.Backend()).markEmailVerified(context.Background(), user.ID))
	hash, err := password.HashArgon2id("Correct-password-12345")
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).upsertPasswordHash(context.Background(), user.ID, hash, "argon2id"))
	return user.ID
}

func testPasskeyFullCeremonyAndAssurance(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Passkeys = PasskeyConfig{
		RPID:             "example.com",
		RPDisplayName:    "Example",
		Origins:          []string{"https://example.com"},
		UserVerification: "preferred",
	}
	srv, err := newServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	user, err := fixtureBackend(srv.Backend()).createUser(ctx, uniqueEmail("passkey-full"), "passkeyfull"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).markEmailVerified(ctx, user.ID))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, user.ID) })

	sid, _, _, err := fixtureBackend(srv.Backend()).issueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := fixtureBackend(srv.Backend()).mintTestAccessToken(ctx, user.ID, map[string]any{"sid": sid})
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
	var created authflow.Passkey
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

	firstAssertion := string(passkeyAssertion(t, authn, assertion, 1))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", firstAssertion)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
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
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(passkeyAssertion(t, authn, assertion, 2)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(passkeyAssertion(t, authn, assertion, 2)))
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_credentials")

	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []authflow.Passkey `json:"data"`
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
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(passkeyAssertion(t, authn, assertion, 3)))
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

func passkeyAssertion(t *testing.T, authn *passkeytest.Authenticator, opts passkeyRequestOptions, signCount uint32) []byte {
	t.Helper()
	return authn.Assertion(t, opts.PublicKey.RPID, opts.PublicKey.Challenge, signCount)
}

var resetVerifySeq atomic.Int64

// lastSent is o's newest kind message, or the zero Message.
func lastSent(o *testoutbox.Outbox, kind testoutbox.Kind) testoutbox.Message {
	msgs := o.Messages(kind, "")
	if len(msgs) == 0 {
		return testoutbox.Message{}
	}
	return msgs[len(msgs)-1]
}

// sentCode is the code of o's newest kind message; the test fails without one.
func sentCode(t *testing.T, o *testoutbox.Outbox, kind testoutbox.Kind) string {
	t.Helper()
	code := lastSent(o, kind).Code
	require.NotEmpty(t, code)
	return code
}

// deviceKeyNotices lists the addresses told of a device-key enrollment.
func deviceKeyNotices(o *testoutbox.Outbox) []string {
	var to []string
	for _, m := range o.Messages(testoutbox.DeviceKeyEnrolled, "") {
		to = append(to, m.To)
	}
	return to
}

func serveJSON(srv *httpapi.Service, method, path, body string) *httptest.ResponseRecorder {
	return serveRequest(srv, method, path, body)
}

func serveRequest(srv *httpapi.Service, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	apiHandler(srv).ServeHTTP(w, r)
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

func passwordlessTestServer(t *testing.T, autoRegister bool) (*httpapi.Service, *testoutbox.Outbox, *testoutbox.Outbox) {
	t.Helper()
	pool := testdb.Pool(t)
	cfg := newServerTestConfig()
	cfg.Frontend.PasswordlessPath = "/wallet/login"
	cfg.Registration.PasswordlessLogin = true
	cfg.Registration.PasswordlessAutoRegistration = autoRegister
	email, sms := &testoutbox.Outbox{}, &testoutbox.Outbox{}
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(email.Email()), withSMSSender(sms.SMS())), WithoutRateLimiter())
	require.NoError(t, err)
	return srv, email, sms
}

// drive runs one group route handler for the group groupID, with the
// caller's claims set, and returns the recorder. Routes with further path
// parameters are driven via driveSub.
func drive(s *httpapi.Service, t *testing.T, gr httpapi.GroupRoute, groupID, caller, body string) *httptest.ResponseRecorder {
	t.Helper()
	path := strings.ReplaceAll(gr.Path, ":group_id", groupID)
	r := httptest.NewRequest(gr.Method, "http://x"+path, strings.NewReader(body))
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.GroupHandler(gr).ServeHTTP(w, r)
	return w
}

// driveSub runs a group route handler at the concrete path repl makes, with
// claims set.
func driveSub(s *httpapi.Service, t *testing.T, gr httpapi.GroupRoute, repl *strings.Replacer, caller string) *httptest.ResponseRecorder {
	t.Helper()
	path := repl.Replace(gr.Path)
	r := httptest.NewRequest(gr.Method, "http://x"+path, nil)
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(verify.SetClaims(r.Context(), verify.Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.GroupHandler(gr).ServeHTTP(w, r)
	return w
}

// withMuxParams rebuilds the request through a one-route ServeMux so r.PathValue
// is populated exactly as it would be in production (PathValue is only set when a
// request is matched by a pattern; httptest.NewRequest alone does not set it).
func withMuxParams(r *http.Request, colonPath string, _ map[string]string) *http.Request {
	pattern := r.Method + " " + httpapi.MuxPath(colonPath)
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

// orgTestConfig declares an "org" persona with remote applications on for
// the role-assignment route.
func orgTestConfig() Config {
	cfg := newServerTestConfig()
	cfg.Roles = RoleConfig{
		Personas: map[string]Persona{"org": {
			Permissions:        []string{"org:catalog:read"},
			RemoteApplications: true,
		}},
		Roles: []Role{
			{Persona: "root", Name: "site-admin", Permissions: []string{iam.PermRootUsersRead.String()}},
			{Persona: "root", Name: "org-admin", Permissions: []string{"org:*"}},
			{Persona: "org", Name: "member", Permissions: []string{"org:catalog:read"}},
			{Persona: "org", Name: "credential-manager", Permissions: []string{"org:credentials:manage", "org:credentials:read"}},
		},
	}
	return cfg
}

func newInstanceTestUser(t *testing.T, srv *httpapi.Service, prefix string) (id, token string) {
	t.Helper()
	ctx := context.Background()
	user, err := fixtureBackend(srv.Backend()).createUser(ctx, uniqueEmail(prefix), prefix+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).markEmailVerified(ctx, user.ID))
	t.Cleanup(func() {
		_, _ = fixtureBackend(srv.Backend()).pg.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	sid, _, _, err := fixtureBackend(srv.Backend()).issueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	tok, _, err := fixtureBackend(srv.Backend()).mintTestAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, tok
}

// testOAuth2Provider is an OAuth2 provider against a fake IdP rooted at base:
// /authorize, /token, and /me returning {id|sub, email, email_verified, login, name}.
func testOAuth2Provider(name, base, clientID, secret string, opts ...authprovider.Option) authprovider.Provider {
	return authprovider.OAuth2(name, base, authprovider.Endpoint{AuthorizeURL: base + "/authorize", TokenURL: base + "/token"},
		clientID, secret, testUserInfo(base+"/me"), append([]authprovider.Option{authprovider.WithTrustedEmailVerification(true)}, opts...)...)
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

// newCookieTestUser creates a password user and returns its id + credentials.
func newCookieTestUser(t *testing.T, pool *pgxpool.Pool, srv *httpapi.Service, prefix string) (email, pass string) {
	t.Helper()
	ctx := context.Background()
	email = uniqueEmail(prefix)
	pass = "correct-horse-battery-97"
	user, err := fixtureBackend(srv.Backend()).createUser(ctx, email, prefix+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).markEmailVerified(ctx, user.ID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).upsertPasswordHash(ctx, user.ID, hash, "argon2id"))
	return email, pass
}

func stalePasswordUserToken(t *testing.T, srv *httpapi.Service, pool *pgxpool.Pool, prefix, pass string) (string, string) {
	t.Helper()
	ctx := context.Background()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := fixtureBackend(srv.Backend()).createUser(ctx, email, username)
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).markEmailVerified(ctx, user.ID))
	t.Cleanup(func() {
		_, _ = fixtureBackend(srv.Backend()).pg.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(srv.Backend()).upsertPasswordHash(ctx, user.ID, hash, "argon2id"))
	sid, _, _, err := fixtureBackend(srv.Backend()).issueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE refresh_sessions SET last_authenticated_at=$1 WHERE id=$2::uuid`, time.Now().Add(-time.Hour), sid)
	require.NoError(t, err)
	token, _, err := fixtureBackend(srv.Backend()).mintTestAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, token
}

// Test-only Config builders: New takes one Config; tests compose it from these
// so a call site names only what it sets. newServer supplies the direct-peer
// posture unless the options declare one.
type Option func(*httpapi.Config)

func WithoutRateLimiter() Option { return func(c *httpapi.Config) { c.Limiter = unlimited{} } }

// unlimited allows every request.
type unlimited struct{}

func (unlimited) AllowNamed(string, string) (bool, error) { return true, nil }

func configOf(opts ...Option) httpapi.Config {
	var c httpapi.Config
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

func newServer(client *Engine, opts ...Option) (*httpapi.Service, error) {
	return newTestService(client, configOf(opts...))
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

func testKeys() KeysConfig {
	s := testSigner()
	return KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}}
}

func newServerTestConfig() Config {
	return Config{
		Keys: testKeys(),
		Token: TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: RegistrationConfig{Verification: iam.RegistrationVerificationNone},
		DeviceKeys:   DeviceKeysConfig{Enabled: true},
		// The harness's IdPs and JWKS endpoints are loopback httptest servers.
		Applications: ApplicationsConfig{AllowPrivateNetworkJWKS: true},
	}
}

// newServerClient builds the embedded engine that a client-first NewServer wraps
// (#142). engineOpts are wired onto the client; HTTP-layer options stay on NewServer.
func newServerClient(t *testing.T, cfg Config, pool *pgxpool.Pool, engineOpts ...coreOpt) *Engine {
	t.Helper()
	c, err := New(context.Background(), cfg, depsOf(append([]coreOpt{withPostgres(pool)}, engineOpts...)...))
	require.NoError(t, err)
	t.Cleanup(c.Close)
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

// failEphemeralWrites makes inserts and updates of ephemeral keys starting
// with prefix fail in Postgres until the returned restore runs.
func failEphemeralWrites(t *testing.T, pool *pgxpool.Pool, prefix string) func() {
	return failEphemeral(t, pool, "INSERT OR UPDATE", "NEW", prefix)
}

// failEphemeralClaims makes deletes (Consume, CompareAndConsume) of ephemeral
// keys starting with prefix fail until the returned restore runs.
func failEphemeralClaims(t *testing.T, pool *pgxpool.Pool, prefix string) func() {
	return failEphemeral(t, pool, "DELETE", "OLD", prefix)
}

func failEphemeral(t *testing.T, pool *pgxpool.Pool, event, row, prefix string) func() {
	t.Helper()
	name := "ephemeral_failure_" + uniqueSuffix()
	_, err := pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ephemeral failure'; END $$;
CREATE TRIGGER %[1]s BEFORE %[2]s ON ephemeral_kv FOR EACH ROW WHEN (%[3]s.key LIKE '%[4]s%%') EXECUTE FUNCTION %[1]s()`, name, event, row, prefix))
	require.NoError(t, err)
	var once sync.Once
	restore := func() {
		once.Do(func() {
			_, err := pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER %[1]s ON ephemeral_kv; DROP FUNCTION %[1]s()`, name))
			require.NoError(t, err)
		})
	}
	t.Cleanup(restore)
	return restore
}

// takeEphemeralOffline makes every ephemeral statement fail until restore.
func takeEphemeralOffline(t *testing.T, pool *pgxpool.Pool) func() {
	t.Helper()
	_, err := pool.Exec(t.Context(), `ALTER TABLE ephemeral_kv RENAME TO ephemeral_kv_offline`)
	require.NoError(t, err)
	var once sync.Once
	restore := func() {
		once.Do(func() {
			_, err := pool.Exec(context.Background(), `ALTER TABLE ephemeral_kv_offline RENAME TO ephemeral_kv`)
			require.NoError(t, err)
		})
	}
	t.Cleanup(restore)
	return restore
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

// One actual HTTP/PG/store rig serves each workflow, including delivery and the
// eventual authenticated request. Delivery is the only substituted boundary.
type accountFlow struct {
	t       *testing.T
	service *httpapi.Service
	server  *httptest.Server
	email   *testoutbox.Outbox
	sms     *testoutbox.Outbox
}

type flowResponse struct {
	status int
	raw    string
	iam.TokenSet
	Tokens      iam.TokenSet `json:"token_set"`
	ReturnTo    string       `json:"return_to"`
	Secret      string       `json:"secret"`
	BackupCodes []string     `json:"backup_codes"`
	Error       struct {
		Code     string `json:"code"`
		Metadata struct {
			UserID           string                            `json:"user_id"`
			Challenge        string                            `json:"challenge"`
			Method           string                            `json:"method"`
			TokenSet         iam.TokenSet                      `json:"token_set"`
			AllowedMethods   []string                          `json:"allowed_methods"`
			AvailableFactors []httpapi.TwoFactorFactorResponse `json:"available_factors"`
			BackupCodes      []string                          `json:"backup_codes"`
		} `json:"metadata"`
	} `json:"error"`
}

func newAccountFlow(t *testing.T, pool *pgxpool.Pool, cfg Config, extra ...coreOpt) *accountFlow {
	t.Helper()
	f := &accountFlow{t: t, email: &testoutbox.Outbox{}, sms: &testoutbox.Outbox{}}
	cfg.Frontend.BaseURL = "https://app.example"
	cfg.Frontend.VerifyPath, cfg.Frontend.PasswordlessPath, cfg.Frontend.PasswordResetPath = "/verify", "/login/link", "/reset"
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef0123456789abcdef")
	opts := []coreOpt{withEmailSender(f.email.Email()), withSMSSender(f.sms.SMS())}
	opts = append(opts, extra...)
	var err error
	f.service, err = newTestService(newServerClient(t, cfg, pool, opts...), workflowHTTPConfig())
	require.NoError(t, err)
	f.mount()
	t.Cleanup(func() { f.server.Close() })
	t.Cleanup(f.service.Close)
	return f
}

func (f *accountFlow) mount() {
	f.t.Helper()
	if f.server != nil {
		f.server.Close()
	}
	mounted, err := httpapi.NewMount(f.service, httpapi.MountOptions{})
	require.NoError(f.t, err)
	f.server = httptest.NewServer(mounted)
	f.server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
}

// Long lifecycle tests share one client IP. Keep the real memory/Redis limiter
// installed without turning repeated legitimate setup into a brute-force test.
// TestWorkflowRateLimits separately proves the small configured boundary.
func workflowHTTPConfig() httpapi.Config {
	limits := httpapi.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = ratelimit.Limit{Limit: 10000, Window: time.Minute}
	}
	return httpapi.Config{DirectPeerIP: true, RateLimits: limits}
}

func (f *accountFlow) request(method, path, token string, body any) flowResponse {
	f.t.Helper()
	data, err := json.Marshal(body)
	require.NoError(f.t, err)
	req, err := http.NewRequest(method, f.server.URL+httpapi.DefaultAPIPath+path, bytes.NewReader(data))
	require.NoError(f.t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.server.Client().Do(req)
	require.NoError(f.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(f.t, err)
	out := flowResponse{status: resp.StatusCode, raw: string(raw)}
	if len(raw) > 0 && resp.Header.Get("Content-Type") == "application/json" {
		require.NoError(f.t, json.Unmarshal(raw, &out), string(raw))
	}
	return out
}

func (f *accountFlow) post(path string, body any) flowResponse {
	return f.request("POST", path, "", body)
}

func (f *accountFlow) expect(status int, r flowResponse) flowResponse {
	f.t.Helper()
	require.Equal(f.t, status, r.status, r.raw)
	return r
}

func (f *accountFlow) session(tokens iam.TokenSet, amr ...string) {
	f.t.Helper()
	require.NotEmpty(f.t, tokens.RefreshToken)
	require.Greater(f.t, tokens.ExpiresIn, int64(0))
	claims, err := f.service.Verifier().Verify(context.Background(), tokens.AccessToken)
	require.NoError(f.t, err)
	require.NotEmpty(f.t, claims.UserID)
	require.ElementsMatch(f.t, amr, claims.AMR)
	f.expect(200, f.request("GET", "/me", tokens.AccessToken, nil))
}

func (f *accountFlow) deliveredLink(raw, path, channel string) string {
	f.t.Helper()
	u, err := url.Parse(raw)
	require.NoError(f.t, err)
	require.Equal(f.t, "https://app.example"+path, u.Scheme+"://"+u.Host+u.Path)
	require.Empty(f.t, u.RawQuery)
	fragment, err := url.ParseQuery(u.Fragment)
	require.NoError(f.t, err)
	require.Equal(f.t, "ready", fragment.Get("status"))
	require.Equal(f.t, channel, fragment.Get("channel"))
	require.NotEmpty(f.t, fragment.Get("token"))
	return fragment.Get("token")
}

func (f *accountFlow) verifyCode(phone bool) string {
	if phone {
		return sentCode(f.t, f.sms, testoutbox.Verification)
	}
	return sentCode(f.t, f.email, testoutbox.Verification)
}

func (f *accountFlow) verifyURL(phone bool) string {
	if phone {
		return lastSent(f.sms, testoutbox.Verification).Link
	}
	return f.email.Last(f.t, testoutbox.Verification, "").Link
}

// flowTOTP is secret's code for the current step.
func flowTOTP(t *testing.T, secret string) string {
	return testTOTPCode(t, secret, time.Now().Unix()/30)
}

func (f *accountFlow) providerLogin(provider authprovider.Provider, identity providerTestIdentity, invite string, browser bool) (flowResponse, url.Values) {
	f.t.Helper()
	begin, err := json.Marshal(map[string]string{"return_to": "/checkout", "account_invite_token": invite})
	require.NoError(f.t, err)
	start, err := f.server.Client().Post(f.server.URL+"/oidc/"+provider.Name()+"/login", "application/json", bytes.NewReader(begin))
	require.NoError(f.t, err)
	defer start.Body.Close()
	require.Equal(f.t, 200, start.StatusCode)
	var begun struct {
		AuthURL string `json:"auth_url"`
	}
	require.NoError(f.t, json.NewDecoder(start.Body).Decode(&begun))
	authURL, err := url.Parse(begun.AuthURL)
	require.NoError(f.t, err)
	identity.Nonce = authURL.Query().Get("nonce")
	raw, err := json.Marshal(identity)
	require.NoError(f.t, err)
	query := url.Values{"state": {authURL.Query().Get("state")}, "code": {base64.RawURLEncoding.EncodeToString(raw)}}
	if !browser {
		query.Set("format", "json")
	}
	req, err := http.NewRequest("GET", f.server.URL+"/oidc/"+provider.Name()+"/callback?"+query.Encode(), nil)
	require.NoError(f.t, err)
	for _, cookie := range start.Cookies() {
		req.AddCookie(cookie)
	}
	callback, err := f.server.Client().Do(req)
	require.NoError(f.t, err)
	defer callback.Body.Close()
	require.Equal(f.t, "no-store", callback.Header.Get("Cache-Control"))
	data, err := io.ReadAll(callback.Body)
	require.NoError(f.t, err)
	out := flowResponse{status: callback.StatusCode, raw: string(data)}
	if browser {
		target, err := url.Parse(callback.Header.Get("Location"))
		require.NoError(f.t, err)
		require.Empty(f.t, target.RawQuery)
		frag, err := url.ParseQuery(target.Fragment)
		require.NoError(f.t, err)
		return out, frag
	}
	require.NoError(f.t, json.Unmarshal(data, &out), string(data))
	return out, nil
}

// The local provider exchanges actual HTTP tokens; OIDC additionally signs and
// verifies an ID token through discovery and JWKS. Only the external IdP is fake.
type providerTestIdentity struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Verified *bool  `json:"email_verified,omitempty"`
	Nonce    string `json:"nonce"`
}

func newSecurityTestProvider(t *testing.T, srv *httpapi.Service, oidc bool) authprovider.Provider {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "provider-test")
	require.NoError(t, err)
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())}})
		case "/token":
			require.NoError(t, r.ParseForm())
			code := r.PostFormValue("code")
			raw, err := base64.RawURLEncoding.DecodeString(code)
			require.NoError(t, err)
			var claims jwt.MapClaims
			require.NoError(t, json.Unmarshal(raw, &claims))
			claims["iss"] = provider.URL
			claims["aud"] = "security-client"
			claims["iat"] = time.Now().Unix()
			claims["exp"] = time.Now().Add(time.Minute).Unix()
			token, err := signer.Sign(r.Context(), claims)
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": code, "token_type": "Bearer", "id_token": token})
		case "/me":
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			require.NoError(t, err)
			_, _ = w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	var cfg authprovider.Provider
	if oidc {
		cfg = authprovider.OIDC("security-provider", provider.URL, "security-client", "local-secret", authprovider.WithTrustedEmailVerification(true))
	} else {
		cfg = testOAuth2Provider("security-provider", provider.URL, "security-client", "local-secret", authprovider.WithScopes("openid", "email", "profile"))
	}
	srv.SetProviders(cfg)
	return cfg
}

// Advancing time is confined to disposable test state. There is no public
// immediate-delete operation or configurable shortened recovery period.
func prepareExpiredDeletion(t *testing.T, s *Engine, userID string) string {
	t.Helper()
	require.NoError(t, s.softDelete(t.Context(), userID))
	_, err := s.pg.Exec(t.Context(), "UPDATE users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", userID)
	require.NoError(t, err)
	var generation string
	require.NoError(t, s.pg.QueryRow(t.Context(), `UPDATE account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours'
 FROM users u WHERE d.user_id=$1::uuid AND d.state='deleted' AND u.id=d.user_id RETURNING d.id::text`, userID).Scan(&generation))
	deliver := func() {
		rows, err := s.pg.Query(t.Context(), "SELECT id FROM account_deletion_deliveries WHERE deletion_id=$1::uuid AND completed_at IS NULL ORDER BY id", generation)
		require.NoError(t, err)
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		require.NoError(t, err)
		for _, id := range ids {
			require.NoError(t, s.deliverAccountEvent(t.Context(), id))
		}
	}
	deliver()
	require.NoError(t, s.finalizeAccountDeletion(t.Context(), generation, false))
	deliver()
	return generation
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
