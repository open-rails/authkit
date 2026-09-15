package authhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// One actual HTTP/PG/store rig serves each workflow, including delivery and the
// eventual authenticated request. Delivery is the only substituted boundary.
type accountFlow struct {
	t       *testing.T
	service *Service
	server  *httptest.Server
	email   *captureEmailSender
	sms     *captureSMSSender
}
type flowResponse struct {
	status int
	raw    string
	authkit.TokenSet
	Tokens      authkit.TokenSet `json:"token_set"`
	ReturnTo    string           `json:"return_to"`
	Secret      string           `json:"secret"`
	BackupCodes []string         `json:"backup_codes"`
	Error       struct {
		Code     string `json:"code"`
		Metadata struct {
			UserID           string                    `json:"user_id"`
			Challenge        string                    `json:"challenge"`
			Method           string                    `json:"method"`
			TokenSet         authkit.TokenSet          `json:"token_set"`
			AllowedMethods   []string                  `json:"allowed_methods"`
			AvailableFactors []twoFactorFactorResponse `json:"available_factors"`
			BackupCodes      []string                  `json:"backup_codes"`
		} `json:"metadata"`
	} `json:"error"`
}

func newAccountFlow(t *testing.T, pool *pgxpool.Pool, store ephemeralStore, cfg embedded.Config) *accountFlow {
	t.Helper()
	f := &accountFlow{t: t, email: &captureEmailSender{}, sms: &captureSMSSender{}}
	cfg.Frontend.BaseURL = "https://app.example"
	cfg.Frontend.VerifyPath, cfg.Frontend.PasswordlessPath, cfg.Frontend.PasswordResetPath = "/verify", "/login/link", "/reset"
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef0123456789abcdef")
	opts := append(store.engineOpts(), withEmailSender(f.email), withSMSSender(f.sms))
	var err error
	f.service, err = newServer(newServerClient(t, cfg, pool, opts...), WithoutRateLimiter())
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/", func(w http.ResponseWriter, r *http.Request) { f.service.oidcHandler().ServeHTTP(w, r) })
	mux.Handle("/", f.service.apiHandler())
	f.server = httptest.NewServer(mux)
	f.server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(f.server.Close)
	t.Cleanup(f.service.Close)
	return f
}
func (f *accountFlow) request(method, path, token string, body any) flowResponse {
	f.t.Helper()
	data, err := json.Marshal(body)
	require.NoError(f.t, err)
	req, err := http.NewRequest(method, f.server.URL+path, bytes.NewReader(data))
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
func (f *accountFlow) session(tokens authkit.TokenSet, amr ...string) {
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
		return f.sms.verificationCode(f.t)
	}
	return f.email.verificationCode(f.t)
}
func (f *accountFlow) verifyURL(phone bool) string {
	if phone {
		f.sms.mu.Lock()
		defer f.sms.mu.Unlock()
		return f.sms.verifyURL
	}
	return f.email.verificationURL(f.t)
}

func TestAccountAdmissionWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		cfg := newServerTestConfig()
		cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
		cfg.Registration.Verification = embedded.RegistrationVerificationRequired
		cfg.Registration.NativeUserMode = embedded.RegistrationModeInviteOnly
		f := newAccountFlow(t, pg.Pool, store, cfg)
		ctx := context.Background()
		inviter, _ := createAccountInvite(t, f.service, pg.Pool, uniqueEmail("unused"))
		for _, phone := range []bool{false, true} {
			for _, passwordless := range []bool{false, true} {
				name := fmt.Sprintf("phone=%t/passwordless=%t", phone, passwordless)
				t.Run(name, func(t *testing.T) {
					f.t = t
					identifier := uniqueEmail("admission")
					channel, method := "email", "email"
					if phone {
						identifier = uniquePhone()
						channel, method = "phone", "sms"
					}
					start, confirm := "/register", "/verify/confirm"
					body := map[string]any{"identifier": identifier, "username": "admit" + uniqueSuffix(), "password": "Correct-horse-battery-1"}
					if passwordless {
						start, confirm = "/passwordless/start", "/passwordless/confirm"
						delete(body, "username")
						delete(body, "password")
						body["mode"] = "both"
						body["return_to"] = "/checkout?plan=pro"
						channel = method
					}
					f.expect(403, f.post(start, body))
					invite, err := f.service.svc.CreateAccountRegistrationInvite(ctx, authkit.CreateAccountRegistrationInviteRequest{Email: uniqueEmail("invite"), InvitedBy: inviter})
					require.NoError(t, err)
					require.Equal(t, invite.URL, f.email.lastInviteURL())
					body["account_invite_token"] = invite.Code
					f.expect(202, f.post(start, body))
					if !passwordless {
						f.expect(401, f.post("/password/login", map[string]any{"identifier": identifier, "password": "wrong"}))
						recovery := f.expect(403, f.post("/password/login", map[string]any{"identifier": identifier, "password": "Correct-horse-battery-1"}))
						require.Equal(t, "verification_required", recovery.Error.Code)
					}

					code := f.verifyCode(phone)
					rawURL := f.verifyURL(phone)
					path := "/verify"
					if passwordless {
						path = "/login/link"
					}
					link := f.deliveredLink(rawURL, path, channel)
					// A code bound to this target cannot authenticate another target, and a
					// failed guess does not consume either representation of the live proof.
					f.expect(400, f.post(confirm, map[string]any{"identifier": uniqueEmail("wrong-target"), "code": code}))
					f.expect(400, f.post(confirm, map[string]any{"identifier": identifier, "code": "WRONG"}))
					var replies [2]flowResponse
					var wg sync.WaitGroup
					for i := range replies {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							proof := map[string]any{"identifier": identifier, "code": code}
							if i == 1 {
								proof = map[string]any{"token": link}
							}
							replies[i] = f.post(confirm, proof)
						}(i)
					}
					wg.Wait()
					winners := 0
					var tokens authkit.TokenSet
					for _, reply := range replies {
						if reply.status == 200 {
							winners++
							tokens = reply.TokenSet
							if passwordless {
								tokens = reply.Tokens
								require.Equal(t, "/checkout?plan=pro", reply.ReturnTo)
							}
						} else {
							require.Equal(t, 400, reply.status, reply.raw)
						}
					}
					require.Equal(t, 1, winners)
					f.session(tokens, method)
					var uid string
					var verified, hasPassword bool
					require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT u.id::text, CASE WHEN $2 THEN u.phone_verified ELSE u.email_verified END, EXISTS(SELECT 1 FROM profiles.user_passwords p WHERE p.user_id=u.id) FROM profiles.users u WHERE CASE WHEN $2 THEN u.phone_number=$1 ELSE u.email=$1 END`, identifier, phone).Scan(&uid, &verified, &hasPassword))
					require.True(t, verified)
					require.Equal(t, !passwordless, hasPassword)
					requireAccountInviteConsumed(t, pg.Pool, invite.ID, uid)
					f.expect(400, f.post(confirm, map[string]any{"token": link}))
					if !passwordless {
						f.expect(200, f.post("/password/login", map[string]any{"identifier": identifier, "password": "Correct-horse-battery-1"}))
						f.expect(200, f.post("/password/login", map[string]any{"identifier": body["username"], "password": "Correct-horse-battery-1"}))
						taken := f.expect(400, f.post("/register", body))
						require.Equal(t, "owner_slug_taken", taken.Error.Code)
					}
				})
			}
		}
		f.t = t
		// Admission is checked again inside account creation, after delivery. A
		// revoked invitation must leave no account or password behind.
		for _, start := range []string{"/register", "/passwordless/start"} {
			email := uniqueEmail("revoked")
			invite, err := f.service.svc.CreateAccountRegistrationInvite(ctx, authkit.CreateAccountRegistrationInviteRequest{Email: email, InvitedBy: inviter})
			require.NoError(t, err)
			payload := map[string]any{"identifier": email, "account_invite_token": invite.Code}
			if start == "/register" {
				payload["username"] = "revoked" + uniqueSuffix()
				payload["password"] = "Correct-horse-battery-1"
			} else {
				payload["mode"] = "both"
			}
			f.expect(202, f.post(start, payload))
			code := f.email.verificationCode(t)
			_, err = pg.Pool.Exec(ctx, `UPDATE profiles.account_registration_invites SET revoked_at=now() WHERE id=$1::uuid`, invite.ID)
			require.NoError(t, err)
			confirm := "/verify/confirm"
			if start == "/passwordless/start" {
				confirm = "/passwordless/confirm"
			}
			reply := f.post(confirm, map[string]any{"identifier": email, "code": code})
			require.GreaterOrEqual(t, reply.status, 400, reply.raw)
			var count int
			require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users WHERE email=$1`, email).Scan(&count))
			require.Zero(t, count)
		}
		for _, body := range []map[string]any{{"identifier": "not-an-identifier", "username": "validname", "password": "Correct-horse-battery-1"}, {"identifier": uniqueEmail("weak"), "username": "validname", "password": "short"}} {
			f.expect(400, f.post("/register", body))
		}

		// Unknown contacts remain undisclosed when automatic signup is disabled.
		disabled := newServerTestConfig()
		noPasswordless := newAccountFlow(t, pg.Pool, store, disabled)
		noPasswordless.expect(404, noPasswordless.post("/passwordless/start", map[string]any{"identifier": uniqueEmail("disabled")}))
		disabled.Registration.PasswordlessLogin = true
		noSignup := newAccountFlow(t, pg.Pool, store, disabled)
		noSignup.expect(202, noSignup.post("/passwordless/start", map[string]any{"identifier": uniqueEmail("unknown")}))
		require.Empty(t, noSignup.email.verifyCode)
		// Generated usernames avoid an existing account's claim.
		username := "collision" + uniqueSuffix()
		_, err := f.service.svc.CreateUser(ctx, uniqueEmail("collision"), username)
		require.NoError(t, err)
		collisionEmail := username + "@example.com"
		invite, err := f.service.svc.CreateAccountRegistrationInvite(ctx, authkit.CreateAccountRegistrationInviteRequest{Email: collisionEmail, InvitedBy: inviter})
		require.NoError(t, err)
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": collisionEmail, "mode": "code", "account_invite_token": invite.Code}))
		f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": collisionEmail, "code": f.email.verificationCode(t)}))
		created, err := f.service.svc.GetUserByEmail(ctx, collisionEmail)
		require.NoError(t, err)
		require.NotEqual(t, username, *created.Username)

		testRegistrationRollback(f, inviter)
		testProofLifecycle(f)
	})
}

func flowTOTP(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func TestAuthenticationContinuationWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		cfg := newServerTestConfig()
		cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
		cfg.TwoFactor.Mode = embedded.TwoFactorRequired
		cfg.Registration.Verification = embedded.RegistrationVerificationRequired
		cfg.Passkeys = embedded.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
		cfg.RBAC = []embedded.PersonaDef{{Name: authkit.RootPersona, Roles: []embedded.RoleDef{{Name: "admin", Permissions: []string{"root:*"}, RequiresMFA: true}}}}
		f := newAccountFlow(t, pg.Pool, store, cfg)
		ctx := context.Background()
		// Registration proof reaches a restricted enrollment token. Complete an
		// independent TOTP proof, then exercise a fresh first factor and MFA login.
		for _, passwordless := range []bool{false, true} {
			t.Run(fmt.Sprint("passwordless=", passwordless), func(t *testing.T) {
				f.t = t
				email := uniqueEmail("continuation")
				start, confirm := "/register", "/verify/confirm"
				if passwordless {
					start, confirm = "/passwordless/start", "/passwordless/confirm"
				}
				payload := map[string]any{"identifier": email}
				if passwordless {
					payload["mode"] = "both"
				} else {
					payload["username"] = "cont" + uniqueSuffix()
					payload["password"] = "Correct-horse-battery-1"
				}
				f.expect(202, f.post(start, payload))
				path := "/verify"
				if passwordless {
					path = "/login/link"
				}
				link := f.deliveredLink(f.email.verificationURL(t), path, "email")
				first := f.expect(403, f.post(confirm, map[string]any{"token": link}))
				require.Equal(t, "2fa_enrollment_required", first.Error.Code)
				assertWireGolden(t, "mfa-enrollment", json.RawMessage(first.raw))
				grant := first.Error.Metadata.TokenSet
				require.NotEmpty(t, grant.AccessToken)
				require.Empty(t, grant.RefreshToken)
				require.NotContains(t, first.Error.Metadata.AllowedMethods, "email", "two proofs sent to one mailbox are one factor")
				require.Contains(t, first.Error.Metadata.AllowedMethods, "totp")
				require.ElementsMatch(t, []any{"email"}, unverifiedAccessClaims(t, grant.AccessToken)["amr"])
				denied := f.request("GET", "/me", grant.AccessToken, nil)
				require.GreaterOrEqual(t, denied.status, 400, denied.raw)
				totp := f.expect(200, f.request("POST", "/user/2fa", grant.AccessToken, map[string]any{"method": "totp"}))
				enabled := f.expect(200, f.request("POST", "/user/2fa", grant.AccessToken, map[string]any{"method": "totp", "code": flowTOTP(t, totp.Secret)}))
				require.NotEmpty(t, enabled.BackupCodes)
				f.session(enabled.Tokens, "email", "totp", "otp", "mfa")
				replay := f.request("POST", "/user/2fa", grant.AccessToken, map[string]any{"method": "sms", "phone": uniquePhone()})
				require.GreaterOrEqual(t, replay.status, 400, replay.raw)
				// Recovery invalidates the captured first factor and its enrollment grant.
				var second flowResponse
				if passwordless {
					f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
					second = f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.email.verificationCode(t)}))
				} else {
					second = f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": "Correct-horse-battery-1"}))
				}
				require.Equal(t, "2fa_required", second.Error.Code)
				require.Equal(t, "totp", second.Error.Metadata.Method)
				assertWireGolden(t, "mfa-challenge", json.RawMessage(second.raw))
				methods := make([]string, 0, len(second.Error.Metadata.AvailableFactors))
				for _, factor := range second.Error.Metadata.AvailableFactors {
					methods = append(methods, factor.Method)
				}
				require.Contains(t, methods, "totp")
				wrong := map[string]any{"user_id": second.Error.Metadata.UserID, "challenge": second.Error.Metadata.Challenge + "x", "code": enabled.BackupCodes[0], "backup_code": true}
				f.expect(401, f.post("/2fa/verify", wrong))
				wrong["challenge"] = second.Error.Metadata.Challenge
				done := f.expect(200, f.post("/2fa/verify", wrong))
				method := "pwd"
				if passwordless {
					method = "email"
				}
				f.session(done.TokenSet, method, "backup_code", "otp", "mfa")
				f.expect(401, f.post("/2fa/verify", wrong))
				f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
				pending := f.expect(403, f.post("/passwordless/confirm", map[string]any{"token": f.email.verificationToken(t)}))
				require.NoError(t, f.service.svc.AdminSetPassword(ctx, pending.Error.Metadata.UserID, "Replacement-password-12345"))
				f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": pending.Error.Metadata.UserID, "challenge": pending.Error.Metadata.Challenge, "code": enabled.BackupCodes[1], "backup_code": true}))
			})
		}
		f.t = t
		phone := uniquePhone()
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": phone, "mode": "code"}))
		phoneGrant := f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": phone, "code": f.sms.verificationCode(t)}))
		require.Equal(t, "2fa_enrollment_required", phoneGrant.Error.Code)
		require.NotContains(t, phoneGrant.Error.Metadata.AllowedMethods, "email", "an email-less account cannot enroll a mailbox factor")
		restricted := phoneGrant.Error.Metadata.TokenSet.AccessToken
		f.expect(400, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "email"}))
		phoneTOTP := f.expect(200, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "totp"}))
		phoneSession := f.expect(200, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "totp", "code": flowTOTP(t, phoneTOTP.Secret)}))
		f.session(phoneSession.Tokens, "sms", "totp", "otp", "mfa")

		f.t = t
		// Email-first plus email-only MFA offers a recovery key, never another code
		// to the same mailbox. A password first factor may use that email factor.
		email := uniqueEmail("same-channel")
		user, err := f.service.svc.CreateUser(ctx, email, "samechannel"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, f.service.svc.AdminSetPassword(ctx, user.ID, "Correct-horse-battery-1"))
		previousCode := f.email.verificationCode(t)
		f.expect(401, f.post("/password/login", map[string]any{"identifier": email, "password": "wrong"}))
		require.Equal(t, previousCode, f.email.verificationCode(t))
		verify := f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": "Correct-horse-battery-1"}))
		require.Equal(t, "verification_required", verify.Error.Code)
		require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))
		backups, err := f.service.svc.Enable2FA(ctx, user.ID, "email", nil, embedded.AllowAdditionalFactors)
		require.NoError(t, err)
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email}))
		ch := f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.email.verificationCode(t)}))
		require.Equal(t, "backup_code", ch.Error.Metadata.Method)
		f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge, "code": f.email.verificationCode(t)}))
		signed := f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge, "code": backups[0], "backup_code": true}))
		f.session(signed.TokenSet, "email", "backup_code", "otp", "mfa")
		ch = f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": "Correct-horse-battery-1"}))
		require.Equal(t, "email", ch.Error.Metadata.Method)
		signed = f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge, "code": f.email.lastLoginCode()}))
		f.session(signed.TokenSet, "pwd", "email", "otp", "mfa")
		testPausedPasswordRecovery(f)
		// A fresh UV passkey satisfies Required mode and an MFA-required role without
		// inventing a second traditional factor. The returned JWT passes /me.
		bootstrapCfg := cfg
		bootstrapCfg.TwoFactor.Mode = embedded.TwoFactorDisabled
		bootstrap := newServerClient(t, bootstrapCfg, pg.Pool, store.engineOpts()...)
		_, err = bootstrap.EnsureRootGroup(ctx)
		require.NoError(t, err)
		passkeyUser, err := bootstrap.CreateUser(ctx, uniqueEmail("uv-role"), "uv"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, bootstrap.AssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(passkeyUser.ID), "admin"))
		authn := passkeytest.New(t, "https://app.example")
		creation, err := f.service.svc.BeginPasskeyRegistration(ctx, passkeyUser.ID)
		require.NoError(t, err)
		createdPasskey, err := f.service.svc.FinishPasskeyRegistration(ctx, passkeyUser.ID, authn.Register(t, creation))
		require.NoError(t, err)
		start := f.expect(200, f.post("/passkeys/login/begin", map[string]any{}))
		var assertion protocol.CredentialAssertion
		require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
		require.Empty(t, assertion.Response.AllowedCredentials)
		uv := f.expect(200, f.post("/passkeys/login/finish", json.RawMessage(authn.Assert(t, &assertion, 1))))
		f.session(uv.TokenSet, "swk", "mfa")
		require.Equal(t, true, unverifiedAccessClaims(t, uv.AccessToken)["mfa_enrolled"])
		start = f.expect(200, f.post("/passkeys/login/begin", map[string]any{}))
		require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
		proof := json.RawMessage(authn.Assert(t, &assertion, 2))
		completed := f.completeWhileRevoking(passkeyUser.ID, func() flowResponse { return f.post("/passkeys/login/finish", proof) }, func(ctx context.Context) error {
			return f.service.svc.DeletePasskey(ctx, passkeyUser.ID, createdPasskey.ID)
		})
		f.expect(200, completed)
		f.session(completed.TokenSet, "swk", "mfa")
		// Revoke-all must see the session committed by refresh-derived MFA, even
		// when revocation began while that completion held the source session.
		optionalCfg := cfg
		optionalCfg.TwoFactor.Mode = embedded.TwoFactorOptional
		old := newAccountFlow(t, pg.Pool, store, optionalCfg)
		refreshUser, err := old.service.svc.CreateUser(ctx, uniqueEmail("revoke-all"), "revall"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, old.service.svc.AdminSetPassword(ctx, refreshUser.ID, "Correct-horse-battery-1"))
		require.NoError(t, old.service.svc.MarkEmailVerified(ctx, refreshUser.ID))
		initial := old.expect(200, old.post("/password/login", map[string]any{"identifier": *refreshUser.Email, "password": "Correct-horse-battery-1"}))
		_, err = f.service.svc.Enable2FA(ctx, refreshUser.ID, "email", nil, embedded.AllowAdditionalFactors)
		require.NoError(t, err)
		needed := f.expect(403, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": initial.RefreshToken}))
		require.Equal(t, "2fa_required", needed.Error.Code)
		completionBody := map[string]any{"user_id": refreshUser.ID, "challenge": needed.Error.Metadata.Challenge, "code": f.email.lastLoginCode()}
		completed = f.completeWhileRevoking(refreshUser.ID, func() flowResponse { return f.post("/2fa/verify", completionBody) }, func(ctx context.Context) error { return f.service.svc.RevokeAllSessions(ctx, refreshUser.ID, nil) })
		f.expect(200, completed)
		var live int
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`, refreshUser.ID).Scan(&live))
		require.Zero(t, live, "revoke-all cannot miss the derived session")

	})
}

func (f *accountFlow) providerLogin(provider authprovider.Provider, identity providerTestIdentity, invite string, browser bool) (flowResponse, url.Values) {
	f.t.Helper()
	start, err := f.server.Client().Get(f.server.URL + "/oidc/" + provider.Name() + "/login?return_to=%2Fcheckout&account_invite_token=" + url.QueryEscape(invite))
	require.NoError(f.t, err)
	defer start.Body.Close()
	require.Equal(f.t, 302, start.StatusCode)
	authURL, err := url.Parse(start.Header.Get("Location"))
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

// OIDC and OAuth2 run the same continuation workflow, including the actual
// token endpoint, browser state cookie, new account transaction and MFA finish.
func TestProviderAuthenticationWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		cfg := newServerTestConfig()
		cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
		cfg.TwoFactor.Mode = embedded.TwoFactorRequired
		f := newAccountFlow(t, pg.Pool, store, cfg)
		for _, oidc := range []bool{true, false} {
			t.Run(fmt.Sprint("oidc=", oidc), func(t *testing.T) {
				f.t = t
				provider := newSecurityTestProvider(t, f.service, oidc)
				verified := true
				identity := providerTestIdentity{Subject: "provider-" + uniqueSuffix(), Email: uniqueEmail("provider-flow"), Verified: &verified}
				first, fragment := f.providerLogin(provider, identity, "", true)
				f.expect(302, first)
				require.Equal(t, "2fa_enrollment_required", fragment.Get("error"))
				require.Equal(t, "/checkout", fragment.Get("return_to"))
				require.Equal(t, provider.Name(), fragment.Get("provider"))
				grant := fragment.Get("enrollment_token")
				require.NotEmpty(t, grant)
				require.Empty(t, fragment.Get("access_token"))
				require.Empty(t, fragment.Get("refresh_token"))
				require.ElementsMatch(t, []any{"oauth"}, unverifiedAccessClaims(t, grant)["amr"])
				var methods []string
				require.NoError(t, json.Unmarshal([]byte(fragment.Get("allowed_methods")), &methods))
				require.Contains(t, methods, "sms")
				phone := uniquePhone()
				f.expect(202, f.request("POST", "/user/2fa", grant, map[string]any{"method": "sms", "phone": phone}))
				enrolled := f.expect(200, f.request("POST", "/user/2fa", grant, map[string]any{"method": "sms", "phone": phone, "code": f.sms.verificationCode(t)}))
				f.session(enrolled.Tokens, "oauth", "sms", "otp", "mfa")
				next, _ := f.providerLogin(provider, identity, "", false)
				f.expect(403, next)
				require.Equal(t, "2fa_required", next.Error.Code)
				require.Equal(t, "sms", next.Error.Metadata.Method)
				finished := f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": next.Error.Metadata.UserID, "challenge": next.Error.Metadata.Challenge, "code": f.sms.lastLoginCode()}))
				f.session(finished.TokenSet, "oauth", "sms", "otp", "mfa")
				require.Equal(t, provider.Name(), unverifiedAccessClaims(t, finished.AccessToken)["provider"])
				// A known provider identity never creates a second account or re-enrolls.
				uid, _, err := f.service.svc.GetProviderLinkByIssuer(t.Context(), provider.Issuer(), identity.Subject)
				require.NoError(t, err)
				require.Equal(t, next.Error.Metadata.UserID, uid)
				// Hold completion after source validation, then unlink concurrently.
				// The source row must remain locked until the session is committed.
				require.NoError(t, f.service.svc.AdminSetPassword(t.Context(), uid, "Provider-backup-password-123"))
				next, _ = f.providerLogin(provider, identity, "", false)
				f.expect(403, next)
				body := map[string]any{"user_id": uid, "challenge": next.Error.Metadata.Challenge, "code": f.sms.lastLoginCode()}
				unlink := func(ctx context.Context) error {
					removed, err := f.service.svc.UnlinkProviderUnlessLast(ctx, uid, provider.Name())
					if err != nil {
						return err
					}
					if !removed {
						return fmt.Errorf("provider unlink refused")
					}
					return nil
				}
				completed := f.completeWhileRevoking(uid, func() flowResponse { return f.post("/2fa/verify", body) }, unlink)
				f.expect(200, completed)
				f.session(completed.TokenSet, "oauth", "sms", "otp", "mfa")
				// Deleting and recreating the same issuer/subject cannot revive a grant
				// that belonged to the previous immutable provider-link row.
				require.NoError(t, f.service.svc.LinkProviderByIssuer(t.Context(), uid, provider.Issuer(), provider.Name(), identity.Subject, nil))
				stale, _ := f.providerLogin(provider, identity, "", false)
				f.expect(403, stale)
				code := f.sms.lastLoginCode()
				require.NoError(t, unlink(t.Context()))
				require.NoError(t, f.service.svc.LinkProviderByIssuer(t.Context(), uid, provider.Issuer(), provider.Name(), identity.Subject, nil))
				f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": uid, "challenge": stale.Error.Metadata.Challenge, "code": code}))

			})
		}
	})
}

func testRegistrationRollback(f *accountFlow, inviter string) {
	t, pool, ctx := f.t, f.service.svc.Postgres(), f.t.Context()
	_, err := pool.Exec(ctx, `CREATE FUNCTION profiles.registration_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected invite consume failure'; END $$; CREATE TRIGGER registration_failure BEFORE UPDATE OF consumed_at ON profiles.account_registration_invites FOR EACH ROW EXECUTE FUNCTION profiles.registration_failure()`)
	require.NoError(t, err)
	defer func() {
		_, err := pool.Exec(ctx, `DROP TRIGGER registration_failure ON profiles.account_registration_invites; DROP FUNCTION profiles.registration_failure()`)
		require.NoError(t, err)
	}()
	for _, flow := range []string{"email", "sms", "passwordless", "oidc", "oauth2"} {
		email, identifier := uniqueEmail("rollback"), ""
		identifier = email
		if flow == "sms" {
			identifier = uniquePhone()
		}
		invite, err := f.service.svc.CreateAccountRegistrationInvite(ctx, authkit.CreateAccountRegistrationInviteRequest{Email: email, InvitedBy: inviter})
		require.NoError(t, err)
		var failed flowResponse
		if flow == "oidc" || flow == "oauth2" {
			provider := newSecurityTestProvider(t, f.service, flow == "oidc")
			verified := true
			failed, _ = f.providerLogin(provider, providerTestIdentity{Subject: "rollback-" + uniqueSuffix(), Email: email, Verified: &verified}, invite.Code, false)
		} else {
			path := "/register"
			body := map[string]any{"identifier": identifier, "account_invite_token": invite.Code}
			if flow == "passwordless" {
				path = "/passwordless/start"
				body["mode"] = "both"
			} else {
				body["username"] = "roll" + uniqueSuffix()
				body["password"] = "Correct-horse-battery-1"
			}
			f.expect(202, f.post(path, body))
			confirm := "/verify/confirm"
			if flow == "passwordless" {
				confirm = "/passwordless/confirm"
			}
			failed = f.post(confirm, map[string]any{"identifier": identifier, "code": f.verifyCode(flow == "sms")})
		}
		require.GreaterOrEqual(t, failed.status, 400, flow+failed.raw)
		var exists, consumed bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.users WHERE email=$1 OR phone_number=$2),(SELECT consumed_at IS NOT NULL FROM profiles.account_registration_invites WHERE id=$3::uuid)`, email, identifier, invite.ID).Scan(&exists, &consumed))
		require.False(t, exists, flow)
		require.False(t, consumed, flow)
	}
}

func testProofLifecycle(f *accountFlow) {
	t, pool, ctx := f.t, f.service.svc.Postgres(), f.t.Context()
	for _, phone := range []bool{false, true} {
		for _, passwordless := range []bool{false, true} {
			identifier := uniqueEmail("lifecycle")
			user, err := f.service.svc.CreateUser(ctx, identifier, "life"+uniqueSuffix())
			require.NoError(t, err)
			if phone {
				identifier = uniquePhone()
				_, err = pool.Exec(ctx, `UPDATE profiles.users SET phone_number=$1,phone_verified=false WHERE id=$2::uuid`, identifier, user.ID)
				require.NoError(t, err)
			}
			start, confirm, path, channel, amr := "/verify/request", "/verify/confirm", "/verify", "email", "email"
			if phone {
				channel, amr = "phone", "sms"
			}
			if passwordless {
				start, confirm, path, channel = "/passwordless/start", "/passwordless/confirm", "/login/link", amr
			}
			begin := func() {
				body := map[string]any{"identifier": identifier}
				if passwordless {
					body["mode"] = "both"
					body["return_to"] = "https://evil.example/steal"
				}
				f.expect(202, f.post(start, body))
			}
			begin()
			stale := f.verifyCode(phone)
			oldLink := f.deliveredLink(f.verifyURL(phone), path, channel)
			begin()
			link := f.deliveredLink(f.verifyURL(phone), path, channel)
			require.NotEqual(t, oldLink, link)
			otherConfirm := "/passwordless/confirm"
			if passwordless {
				otherConfirm = "/verify/confirm"
			}
			f.expect(400, f.post(otherConfirm, map[string]any{"token": link}))
			f.expect(400, f.post(confirm, map[string]any{"token": oldLink}))
			f.expect(400, f.post(confirm, map[string]any{"identifier": identifier, "code": stale}))
			// Guess budget survives reissue; four misses remain live, the fifth burns
			// both the code and its alternate link representation.
			for i := 0; i < 3; i++ {
				f.expect(400, f.post(confirm, map[string]any{"identifier": identifier, "code": "WRONG"}))
			}
			begin()
			link = f.deliveredLink(f.verifyURL(phone), path, channel)
			f.expect(400, f.post(confirm, map[string]any{"identifier": identifier, "code": "WRONG"}))
			f.expect(400, f.post(confirm, map[string]any{"token": link}))
			begin()
			current := f.verifyCode(phone)
			link = f.deliveredLink(f.verifyURL(phone), path, channel)
			done := f.expect(200, f.post(confirm, map[string]any{"identifier": identifier, "code": current}))
			tokens := done.TokenSet
			if passwordless {
				tokens = done.Tokens
				require.Empty(t, done.ReturnTo)
			}
			f.session(tokens, amr)
			f.expect(400, f.post(confirm, map[string]any{"token": link}))
			// The reverse order (link then code) has the same canonical winner. Existing
			// accounts remain available in InviteOnly mode without spending another invite.
			if passwordless {
				begin()
				current = f.verifyCode(phone)
				link = f.deliveredLink(f.verifyURL(phone), path, channel)
				done = f.expect(200, f.post(confirm, map[string]any{"token": link}))
				f.session(done.Tokens, amr)
				f.expect(400, f.post(confirm, map[string]any{"identifier": identifier, "code": current}))
			}
		}
	}
	// Completion paused on the account lock must not delete a newer issuance.
	email := uniqueEmail("reissue")
	user, err := f.service.svc.CreateUser(ctx, email, "reissue"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))
	begin := func() {
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
	}
	begin()
	old := f.email.verificationCode(t)
	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, `SELECT id FROM profiles.users WHERE id=$1::uuid FOR UPDATE`, user.ID)
	require.NoError(t, err)
	completed := make(chan flowResponse, 1)
	go func() { completed <- f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": old}) }()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
		return err == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	begin()
	newCode := f.email.verificationCode(t)
	require.NoError(t, lock.Commit(ctx))
	f.expect(200, <-completed)
	f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": newCode}))
}

func testPausedPasswordRecovery(f *accountFlow) {
	t, pool, ctx := f.t, f.service.svc.Postgres(), f.t.Context()
	user, err := f.service.svc.CreateUser(ctx, uniqueEmail("paused-password"), "paused"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, f.service.svc.AdminSetPassword(ctx, user.ID, "Original-password-12345"))
	require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))
	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, `SELECT id FROM profiles.users WHERE id=$1::uuid FOR UPDATE`, user.ID)
	require.NoError(t, err)
	changed := make(chan error, 1)
	go func() { changed <- f.service.svc.AdminSetPassword(ctx, user.ID, "Replacement-password-12345") }()
	waitLocks := func(want int) {
		require.Eventually(t, func() bool {
			var n int
			err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
			return err == nil && n == want
		}, 5*time.Second, 10*time.Millisecond)
	}
	waitLocks(1)
	login := make(chan flowResponse, 1)
	go func() {
		login <- f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Original-password-12345"})
	}()
	waitLocks(2)
	require.NoError(t, lock.Commit(ctx))
	require.NoError(t, <-changed)
	f.expect(401, <-login)
	var sessions int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1::uuid`, user.ID).Scan(&sessions))
	require.Zero(t, sessions, "a password check preceding completed recovery cannot mint a session")
}
