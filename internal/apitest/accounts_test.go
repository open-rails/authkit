package apitest_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/naming"
	"github.com/open-rails/authkit/internal/testidp"
)

var seq atomic.Int64

// unique is prefix plus a number no other call in the process returns.
func unique(prefix string) string { return fmt.Sprintf("%s%d", prefix, seq.Add(1)) }

func uniqueEmail(prefix string) string { return unique(prefix) + "@example.com" }

func uniquePhone() string { return fmt.Sprintf("+1555%07d", seq.Add(1)) }

// profile is GET /me.
type profile struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	EmailVerified bool   `json:"email_verified"`
	PhoneVerified bool   `json:"phone_verified"`
	HasPassword   bool   `json:"has_password"`
	Naming        struct {
		Aliases      []naming.Alias `json:"aliases"`
		Allowed      bool           `json:"allowed"`
		NextRenameAt *time.Time     `json:"next_rename_at"`
	} `json:"naming"`
}

func (a *api) me(t *testing.T, token string) profile {
	t.Helper()
	res := a.get("/me", token)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var p profile
	res.decode(t, &p)
	return p
}

// Invite-only admission by email and phone, registration and passwordless:
// the invitation, the proof of the contact (a code or a link, one winner) and
// the account they make; then how proofs of existing accounts are reissued,
// guessed and spent.
func TestAccountAdmissionWorkflow(t *testing.T) {
	rbac := authkit.NewRoles()
	inviterRole := rbac.Root.Role("inviter", rbac.Root.Users.Invite)
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		withAppLinks(c)
		c.Roles = rbac
		c.Registration = authkit.RegistrationConfig{
			Verification:      iam.RegistrationVerificationRequired,
			NativeUserMode:    iam.RegistrationModeInviteOnly,
			PasswordlessLogin: true, PasswordlessAutoRegistration: true,
		}
	}))
	a := newAPI(t, auth)
	ctx := t.Context()
	const password = "Correct-horse-battery-1"
	newInviter := func(t *testing.T) string {
		u := authtest.NewUser(t, auth)
		authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(u.ID), inviterRole)
		return u.ID
	}
	invite := func(t *testing.T, inviter, email string) iam.InvitationCreated {
		t.Helper()
		created, err := auth.CreateInvitation(ctx, iam.UserActor(inviter), iam.RootGroup(), iam.NewInvitation{Email: email})
		require.NoError(t, err)
		require.Equal(t, created.URL, outbox.Last(t, iam.MessageInvite, email).Link)
		return created
	}
	inviter := newInviter(t)

	for _, phone := range []bool{false, true} {
		for _, passwordless := range []bool{false, true} {
			t.Run(fmt.Sprintf("phone=%t/passwordless=%t", phone, passwordless), func(t *testing.T) {
				a := newAPI(t, auth)
				identifier := uniqueEmail("admission")
				channel, method := "email", "email"
				newIdentifier := func() string { return uniqueEmail("admission") }
				if phone {
					identifier = uniquePhone()
					channel, method = "phone", "sms"
					newIdentifier = uniquePhone
				}
				start, confirm := "/register", "/verify/confirm"
				body := map[string]any{"identifier": identifier, "username": unique("admit"), "password": password}
				if passwordless {
					start, confirm = "/passwordless/start", "/passwordless/confirm"
					delete(body, "username")
					delete(body, "password")
					body["mode"] = "both"
					body["return_to"] = "/checkout?plan=pro"
					channel = method
				}
				expect(t, http.StatusForbidden, a.post(start, "", body))
				invitation := invite(t, inviter, uniqueEmail("invite"))
				body["invite_code"] = invitation.Code
				expect(t, http.StatusAccepted, a.post(start, "", body))
				if !passwordless {
					expect(t, http.StatusUnauthorized, a.post("/password/login", "", map[string]any{"identifier": identifier, "password": "wrong"}))
					pending := a.post("/password/login", "", map[string]any{"identifier": identifier, "password": password}).answer(t).step(t, httpapi.AuthVerificationRequired)
					require.Equal(t, httpapi.VerificationStep{Identifier: identifier, Channel: channel}, *pending.Verification)
				}

				sent := outbox.Last(t, iam.MessageVerification, identifier)
				path := "/verify"
				if passwordless {
					path = "/login/link"
				}
				link := deliveredLink(t, sent.Link, path, channel)
				// A code bound to this target cannot authenticate another target, and a
				// failed guess does not consume either representation of the live proof.
				expect(t, http.StatusUnauthorized, a.post(confirm, "", map[string]any{"identifier": uniqueEmail("wrong-target"), "code": sent.Code}))
				expect(t, http.StatusUnauthorized, a.post(confirm, "", map[string]any{"identifier": identifier, "code": "WRONG"}))
				var replies [2]response
				var errs [2]error
				var wg sync.WaitGroup
				for i := range replies {
					wg.Go(func() {
						proof := map[string]any{"identifier": identifier, "code": sent.Code}
						if i == 1 {
							proof = map[string]any{"token": link}
						}
						replies[i], errs[i] = a.send(request{method: http.MethodPost, path: confirm, body: proof})
					})
				}
				wg.Wait()
				winners := 0
				var tokens iam.TokenSet
				for i, reply := range replies {
					require.NoError(t, errs[i])
					if reply.status == http.StatusOK {
						winners++
						session := reply.answer(t)
						tokens = session.signedIn(t)
						require.True(t, session.Created, "the proof created the account")
						if passwordless {
							require.Equal(t, "/checkout?plan=pro", *session.ReturnTo)
						}
					} else {
						require.Equal(t, [2]int{http.StatusUnauthorized, http.StatusBadRequest}[i], reply.status, reply.String()) // spent code, spent link
					}
				}
				require.Equal(t, 1, winners)
				claims := requireSessionWith(t, a, auth, tokens, method)
				account := a.me(t, tokens.AccessToken)
				require.Equal(t, claims.UserID, account.ID)
				ref := iam.UserByEmail(identifier)
				if phone {
					ref = iam.UserByPhone(identifier)
				}
				user, err := auth.User(ctx, ref)
				require.NoError(t, err)
				require.Equal(t, account.ID, user.ID)
				verified, shown := user.EmailVerified, account.EmailVerified
				if phone {
					verified, shown = user.PhoneVerified, account.PhoneVerified
				}
				require.True(t, verified)
				require.True(t, shown)
				require.Equal(t, !passwordless, account.HasPassword)
				// The invitation is spent: it admits nobody else.
				again := map[string]any{}
				for k, v := range body {
					again[k] = v
				}
				again["identifier"] = newIdentifier()
				if !passwordless {
					again["username"] = unique("admit")
				}
				expect(t, http.StatusForbidden, a.post(start, "", again))
				expect(t, http.StatusBadRequest, a.post(confirm, "", map[string]any{"token": link}))
				if !passwordless {
					expect(t, http.StatusOK, a.post("/password/login", "", map[string]any{"identifier": identifier, "password": password}))
					expect(t, http.StatusOK, a.post("/password/login", "", map[string]any{"identifier": body["username"], "password": password}))
					taken := expect(t, http.StatusBadRequest, a.post("/register", "", body))
					require.Equal(t, "username_in_use", taken.code())
				}
			})
		}
	}

	// Admission is checked again inside account creation, after delivery. An
	// invitation that died since (its inviter banned) leaves no account behind.
	for _, start := range []string{"/register", "/passwordless/start"} {
		email := uniqueEmail("revoked")
		issuer := newInviter(t)
		payload := map[string]any{"identifier": email, "invite_code": invite(t, issuer, email).Code}
		confirm := "/verify/confirm"
		if start == "/register" {
			payload["username"] = unique("revoked")
			payload["password"] = password
		} else {
			payload["mode"] = "both"
			confirm = "/passwordless/confirm"
		}
		expect(t, http.StatusAccepted, a.post(start, "", payload))
		code := outbox.Last(t, iam.MessageVerification, email).Code
		require.NotEmpty(t, code)
		require.NoError(t, auth.Ban(ctx, iam.SystemActor(), issuer, iam.Ban{}))
		reply := a.post(confirm, "", map[string]any{"identifier": email, "code": code})
		require.GreaterOrEqual(t, reply.status, 400, reply.String())
		_, err := auth.User(ctx, iam.UserByEmail(email), authkit.IncludeDeleted())
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	}
	for _, body := range []map[string]any{
		{"identifier": "not-an-identifier", "username": "validname", "password": password},
		{"identifier": uniqueEmail("weak"), "username": "validname", "password": "short"},
	} {
		expect(t, http.StatusBadRequest, a.post("/register", "", body))
	}

	// Unknown contacts remain undisclosed when automatic signup is disabled.
	closed := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Registration = authkit.RegistrationConfig{} }))
	expect(t, http.StatusNotFound, newAPI(t, closed).post("/passwordless/start", "", map[string]any{"identifier": uniqueEmail("disabled")}))
	noSignup := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
		c.Registration = authkit.RegistrationConfig{PasswordlessLogin: true}
	}))
	unknown := uniqueEmail("unknown")
	expect(t, http.StatusAccepted, newAPI(t, noSignup).post("/passwordless/start", "", map[string]any{"identifier": unknown}))
	for _, m := range outbox.Messages(iam.MessageVerification, unknown) {
		require.Empty(t, m.Code)
	}

	// Generated usernames avoid an existing account's claim.
	username := unique("collision")
	_, err := auth.CreateUser(ctx, iam.NewUser{Email: uniqueEmail("collision"), Username: username})
	require.NoError(t, err)
	collisionEmail := username + "@example.com"
	expect(t, http.StatusAccepted, a.post("/passwordless/start", "", map[string]any{"identifier": collisionEmail, "mode": "code", "invite_code": invite(t, inviter, collisionEmail).Code}))
	expect(t, http.StatusOK, a.post("/passwordless/confirm", "", map[string]any{"identifier": collisionEmail, "code": outbox.Last(t, iam.MessageVerification, collisionEmail).Code}))
	created, err := auth.User(ctx, iam.UserByEmail(collisionEmail))
	require.NoError(t, err)
	require.NotEqual(t, username, created.Username)

	testProofLifecycle(t, auth, a, outbox)
}

// testProofLifecycle runs each proof of an existing account (a contact
// verification or a passwordless sign-in, by email or phone): reissue retires
// the earlier proof, the guess budget survives reissue, and a code and its link
// have one winner in either order.
func testProofLifecycle(t *testing.T, auth *authkit.Client, a *api, outbox *authtest.Outbox) {
	ctx := t.Context()
	for _, phone := range []bool{false, true} {
		for _, passwordless := range []bool{false, true} {
			identifier := uniqueEmail("lifecycle")
			account := iam.NewUser{Email: identifier, Username: unique("life")}
			if phone {
				identifier = uniquePhone()
				account.Phone = identifier
			}
			_, err := auth.CreateUser(ctx, account)
			require.NoError(t, err)
			start, confirm, path, channel, amr := "/verify/request", "/verify/confirm", "/verify", "email", "email"
			if phone {
				channel, amr = "phone", "sms"
			}
			if passwordless {
				start, confirm, path, channel = "/passwordless/start", "/passwordless/confirm", "/login/link", amr
			}
			begin := func() authtest.Message {
				t.Helper()
				body := map[string]any{"identifier": identifier}
				if passwordless {
					body["mode"] = "both"
					body["return_to"] = "https://evil.example/steal"
				}
				expect(t, http.StatusAccepted, a.post(start, "", body))
				return outbox.Last(t, iam.MessageVerification, identifier)
			}
			first := begin()
			stale := first.Code
			oldLink := deliveredLink(t, first.Link, path, channel)
			link := deliveredLink(t, begin().Link, path, channel)
			require.NotEqual(t, oldLink, link)
			otherConfirm := "/passwordless/confirm"
			if passwordless {
				otherConfirm = "/verify/confirm"
			}
			expect(t, http.StatusBadRequest, a.post(otherConfirm, "", map[string]any{"token": link}))
			expect(t, http.StatusBadRequest, a.post(confirm, "", map[string]any{"token": oldLink}))
			expect(t, http.StatusUnauthorized, a.post(confirm, "", map[string]any{"identifier": identifier, "code": stale}))
			// Guess budget survives reissue; four misses remain live, the fifth burns
			// both the code and its alternate link representation.
			for range 3 {
				expect(t, http.StatusUnauthorized, a.post(confirm, "", map[string]any{"identifier": identifier, "code": "WRONG"}))
			}
			link = deliveredLink(t, begin().Link, path, channel)
			expect(t, http.StatusUnauthorized, a.post(confirm, "", map[string]any{"identifier": identifier, "code": "WRONG"}))
			expect(t, http.StatusBadRequest, a.post(confirm, "", map[string]any{"token": link}))
			sent := begin()
			link = deliveredLink(t, sent.Link, path, channel)
			done := expect(t, http.StatusOK, a.post(confirm, "", map[string]any{"identifier": identifier, "code": sent.Code})).answer(t)
			require.Nil(t, done.ReturnTo, "an off-site return_to is dropped")
			require.False(t, done.Created)
			requireSessionWith(t, a, auth, done.signedIn(t), amr)
			expect(t, http.StatusBadRequest, a.post(confirm, "", map[string]any{"token": link}))
			// The reverse order (link then code) has the same canonical winner. Existing
			// accounts remain available in InviteOnly mode without spending another invite.
			if passwordless {
				sent = begin()
				link = deliveredLink(t, sent.Link, path, channel)
				done = expect(t, http.StatusOK, a.post(confirm, "", map[string]any{"token": link})).answer(t)
				requireSessionWith(t, a, auth, done.signedIn(t), amr)
				expect(t, http.StatusUnauthorized, a.post(confirm, "", map[string]any{"identifier": identifier, "code": sent.Code}))
			}
		}
	}
}

// The Client reads an account's application metadata as a copy.
func TestClientReadsUserMetadata(t *testing.T) {
	auth, _ := authtest.New(t)
	ctx := t.Context()
	imported, err := auth.ImportUsers(ctx, []iam.ImportUser{{Email: "metadata-client@example.test", Username: "metadata-client",
		Metadata: map[string]any{"biography": "Public bio", "host_private": "not automatically public"}}}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, imported.Inserted)
	id := imported.Rows[0].UserID
	data, err := auth.UserMetadata(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "Public bio", data["biography"])
	require.Equal(t, "not automatically public", data["host_private"])
	data["biography"] = "local mutation"
	again, err := auth.UserMetadata(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "Public bio", again["biography"])
	_, err = auth.UserMetadata(ctx, uuid.NewString())
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	_, err = auth.UserMetadata(ctx, "")
	require.ErrorIs(t, err, iam.ErrUserNotFound)
}

// A password change against an imported legacy reset-required hash answers
// the catalog's 401 password_reset_required, from a fresh session too.
func TestPasswordChangeOnLegacyHashRequiresReset(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		withAppLinks(c)
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Registration.PasswordlessLogin = true
	}))
	a := newAPI(t, auth)
	const email = "legacy@example.test"
	imported, err := auth.ImportUsers(t.Context(), []iam.ImportUser{{Email: email, EmailVerified: true, Username: "legacyuser",
		PasswordHash: &iam.PasswordHash{Hash: "legacy-digest", Algo: iam.HashLegacyResetRequired}}}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, imported.Inserted, "%+v", imported.Rows)
	// A passwordless sign-in: a fresh session without the password.
	res := a.post("/passwordless/start", "", map[string]any{"identifier": email, "mode": "code"})
	require.Equal(t, http.StatusAccepted, res.status, res.String())
	res = a.post("/passwordless/confirm", "", map[string]any{"identifier": email, "code": outbox.Last(t, iam.MessageVerification, email).Code})
	require.Equal(t, http.StatusOK, res.status, res.String())
	token := res.answer(t).signedIn(t).AccessToken
	require.NotEmpty(t, token)

	res = a.post("/user/password", token, map[string]any{"current_password": "Correct-horse-battery-7", "new_password": "Another-horse-battery-8"})
	require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	require.Equal(t, "password_reset_required", res.code())
}

// A username is one identity in every case: the owner's spelling is kept for
// display, and registration, pending holds, login and availability all treat
// other spellings as that same account. A change of case is not a rename.
func TestUsernameCaseWorkflow(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		withAppLinks(c)
		c.Registration.Verification = iam.RegistrationVerificationRequired
		c.Username.Renames = true
	}))
	a := newAPI(t, auth)
	ctx := t.Context()
	name := unique("Fidika")
	lower, upper := strings.ToLower(name), strings.ToUpper(name)
	const pass = "Correct-horse-battery-1"
	owner := uniqueEmail("case-owner")

	expect(t, http.StatusAccepted, a.post("/register", "", map[string]any{"identifier": owner, "username": name, "password": pass}))
	held := expect(t, http.StatusBadRequest, a.post("/register", "", map[string]any{"identifier": uniqueEmail("case-pending"), "username": lower, "password": pass}))
	require.Equal(t, "username_in_use", held.code(), "a pending signup holds every spelling of its name")

	confirmed := expect(t, http.StatusOK, a.post("/verify/confirm", "", map[string]any{"identifier": owner, "code": outbox.Last(t, iam.MessageVerification, owner).Code})).answer(t).signedIn(t)
	claims, err := auth.Verify(ctx, confirmed.AccessToken)
	require.NoError(t, err)
	userID := claims.UserID
	require.Equal(t, name, a.me(t, confirmed.AccessToken).Username, "display keeps the chosen spelling")

	// Three sign-ins fill the session cap and evict the confirmation's session;
	// the last one's token is live.
	var live string
	for _, spelling := range []string{name, lower, upper} {
		login := expect(t, http.StatusOK, a.post("/password/login", "", map[string]any{"identifier": spelling, "password": pass})).answer(t).signedIn(t)
		got, err := auth.Verify(ctx, login.AccessToken)
		require.NoError(t, err)
		require.Equal(t, userID, got.UserID, "login as %s", spelling)
		live = login.AccessToken
	}

	taken := expect(t, http.StatusBadRequest, a.post("/register", "", map[string]any{"identifier": uniqueEmail("case-dup"), "username": upper, "password": pass}))
	require.Equal(t, "username_in_use", taken.code())
	for _, spelling := range []string{name, lower, upper} {
		resolved, err := auth.ResolveUsername(ctx, spelling)
		require.NoError(t, err)
		require.Equal(t, userID, resolved.ID, "one account holds %s", spelling)
		require.False(t, resolved.IsAlias)
	}

	availability := expect(t, http.StatusOK, a.get("/register/availability?username="+url.QueryEscape(lower), ""))
	var answer struct {
		Username struct {
			Available bool `json:"available"`
		} `json:"username"`
	}
	availability.decode(t, &answer)
	require.False(t, answer.Username.Available)

	evicted := expect(t, http.StatusUnauthorized, a.do(request{method: http.MethodPatch, path: "/user/username", token: confirmed.AccessToken, body: map[string]any{"username": lower}}))
	require.Equal(t, "session_revoked", evicted.code(), "an evicted session changes nothing")
	renamed := expect(t, http.StatusOK, a.do(request{method: http.MethodPatch, path: "/user/username", token: live, body: map[string]any{"username": lower}}))
	require.Contains(t, renamed.String(), `"username":"`+lower+`"`)
	me := a.me(t, live)
	require.Equal(t, lower, me.Username)
	require.True(t, me.Naming.Allowed, "a case change is not a rename")
	require.Nil(t, me.Naming.NextRenameAt, "a case change is not a rename")
	require.Empty(t, me.Naming.Aliases, "a case change leaves no alias")
	resolved, err := auth.ResolveUsername(ctx, name)
	require.NoError(t, err)
	require.Equal(t, iam.NameResolution{ID: userID, CanonicalName: lower}, resolved)
	expect(t, http.StatusOK, a.post("/password/login", "", map[string]any{"identifier": name, "password": pass}))
	expect(t, http.StatusOK, a.do(request{method: http.MethodPatch, path: "/user/username", token: live, body: map[string]any{"username": unique("renamed")}}))
}

// policyError checks res is the 400 a policy refusal is, on param, and returns
// its metadata.
func policyError(t *testing.T, res response, code, param string) map[string]any {
	t.Helper()
	var env struct {
		Error struct {
			Code     string         `json:"code"`
			Param    string         `json:"param"`
			Metadata map[string]any `json:"metadata"`
		} `json:"error"`
	}
	require.Equal(t, http.StatusBadRequest, res.status, res.String())
	res.decode(t, &env)
	require.Equal(t, code, env.Error.Code, res.String())
	require.Equal(t, param, env.Error.Param)
	return env.Error.Metadata
}

// Each deployment's password and username policy is published at
// /capabilities and enforced wherever a password or username is set:
// registration, a password change, a reset, a rename, an import and New.
func TestAccountPolicies(t *testing.T) {
	type policies struct {
		Password map[string]any `json:"password"`
		Username map[string]any `json:"username"`
	}
	setup := func(t *testing.T, fn func(*authkit.Config), opts ...authtest.Option) (*authkit.Client, *api, policies) {
		auth, _ := authtest.New(t, append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
			withAppLinks(c)
			c.TwoFactor.Mode = iam.TwoFactorDisabled
			fn(c)
		})}, opts...)...)
		a := newAPI(t, auth)
		caps := a.get("/capabilities", "")
		require.Equal(t, http.StatusOK, caps.status, caps.String())
		var wire policies
		caps.decode(t, &wire)
		return auth, a, wire
	}
	register := func(a *api, email, username, pass string) response {
		return a.post("/register", "", map[string]any{"identifier": email, "username": username, "password": pass})
	}
	registered := func(t *testing.T, res response) string {
		t.Helper()
		require.Equal(t, http.StatusOK, res.status, res.String())
		token := res.answer(t).signedIn(t).AccessToken
		require.NotEmpty(t, token)
		return token
	}
	change := func(a *api, token, current, next string) response {
		return a.post("/user/password", token, map[string]any{"current_password": current, "new_password": next})
	}

	t.Run("configured length", func(t *testing.T) {
		_, a, wire := setup(t, func(c *authkit.Config) {
			c.Password = &authkit.PasswordPolicy{MinLength: 12, MaxLength: 20}
		})
		require.Equal(t, map[string]any{"min_length": float64(12), "max_length": float64(20),
			"require_uppercase": false, "require_lowercase": false, "require_digit": false, "require_symbol": false, "allow_common": false}, wire.Password)
		bounds := map[string]any{"min_length": float64(12), "max_length": float64(20)}
		require.Equal(t, bounds, policyError(t, register(a, "policy@example.test", "policyuser", "elevenchars"), "password_too_short", "password"))
		require.Equal(t, bounds, policyError(t, register(a, "policy@example.test", "policyuser", strings.Repeat("x", 21)), "password_too_long", "password"))
		// Length is counted in characters: 12 two-byte runes pass a 20-character maximum.
		pass := strings.Repeat("é", 12)
		token := registered(t, register(a, "policy@example.test", "policyuser", pass))
		require.Equal(t, bounds, policyError(t, change(a, token, pass, "short-pass"), "password_too_short", "password"))
		require.Equal(t, bounds, policyError(t, change(a, token, pass, strings.Repeat("y", 21)), "password_too_long", "password"))
		require.Equal(t, bounds, policyError(t, a.post("/password/reset/confirm", "", map[string]any{"token": "unused", "new_password": "short-pass"}), "password_too_short", "password"))
		res := change(a, token, pass, "twelve-chars")
		require.Equal(t, http.StatusNoContent, res.status, res.String())
	})

	t.Run("default rejects common and identifier passwords", func(t *testing.T) {
		_, a, wire := setup(t, func(*authkit.Config) {})
		require.Equal(t, map[string]any{"min_length": float64(8), "max_length": float64(128),
			"require_uppercase": false, "require_lowercase": false, "require_digit": false, "require_symbol": false, "allow_common": false}, wire.Password)
		require.Equal(t, map[string]any{"min_length": float64(4), "max_length": float64(30), "pattern": naming.UsernamePattern,
			"renames": false, "rename_interval_seconds": config.DefaultRenameInterval.Seconds(),
			"former_names": map[string]any{"enabled": false, "former_name_retention_mode": string(config.FormerNamesFinite),
				"former_name_retention_seconds": config.DefaultFormerNameRetention.Seconds()}}, wire.Username)
		require.Nil(t, policyError(t, register(a, "common@example.test", "commonuser", "QwertyUIOP"), "password_too_common", "password"))
		for _, common := range []string{"password123", "Password1!", "qwerty12345", "iloveyou123"} {
			policyError(t, register(a, "common@example.test", "commonuser", common), "password_too_common", "password")
		}
		policyError(t, register(a, "common@example.test", "commonuser", "my-commonuser-pass"), "password_contains_identifier", "password")
		policyError(t, register(a, "mailbox.owner@example.test", "someoneelse", "xx-MAILBOX.OWNER-xx"), "password_contains_identifier", "password")
		token := registered(t, register(a, "common@example.test", "commonuser", "violet-harbor-lantern"))
		policyError(t, change(a, token, "violet-harbor-lantern", "iloveyou1"), "password_too_common", "password")
		policyError(t, change(a, token, "violet-harbor-lantern", "renamed-COMMONUSER-1"), "password_contains_identifier", "password")
	})

	t.Run("host composition and username bounds", func(t *testing.T) {
		_, a, wire := setup(t, func(c *authkit.Config) {
			c.Password = &authkit.PasswordPolicy{RequireSymbol: true, RequireDigit: true, AllowCommon: true}
			c.Username = authkit.UsernameConfig{MinLength: 6, MaxLength: 12, Renames: true}
		})
		require.Equal(t, true, wire.Password["require_symbol"])
		require.Equal(t, true, wire.Password["require_digit"])
		require.Equal(t, true, wire.Password["allow_common"])
		require.Equal(t, float64(6), wire.Username["min_length"])
		require.Equal(t, float64(12), wire.Username["max_length"])
		bounds := map[string]any{"min_length": float64(6), "max_length": float64(12)}
		missing := policyError(t, register(a, "compose@example.test", "composer", "lettersonly"), "password_requirements_unmet", "password")
		require.Equal(t, []any{"digit", "symbol"}, missing["missing"])
		require.Equal(t, bounds, policyError(t, register(a, "compose@example.test", "compo", "abc-12345"), "username_too_short", "username"))
		require.Equal(t, bounds, policyError(t, register(a, "compose@example.test", "composer_long", "abc-12345"), "username_too_long", "username"))
		policyError(t, register(a, "compose@example.test", "1composer", "abc-12345"), "username_must_start_with_letter", "username")
		token := registered(t, register(a, "compose@example.test", "composer", "password1!"))
		rename := a.do(request{method: http.MethodPatch, path: "/user/username", token: token, body: map[string]any{"username": "abc"}})
		require.Equal(t, bounds, policyError(t, rename, "username_too_short", "username"))
	})

	t.Run("username policy bounds derived and imported names and New", func(t *testing.T) {
		idp := testidp.New(t)
		auth, a, _ := setup(t, func(c *authkit.Config) {
			c.Username = authkit.UsernameConfig{MinLength: 8, MaxLength: 10}
		}, withProviders(idp.OIDC("idp")))
		ctx := t.Context()
		// A provider sign-up derives its username from the email's local part,
		// padded to the policy's minimum.
		derived := func(subject, email string) string {
			t.Helper()
			expectAnswer(t, providerSignIn(t, a, idp, "idp", testidp.Identity{Subject: subject, Email: email, EmailVerified: true}, ""), http.StatusOK)
			u, err := auth.User(ctx, iam.UserByEmail(email))
			require.NoError(t, err)
			return u.Username
		}
		require.Equal(t, "ab_user_us", derived("first", "ab@example.test"))
		second := derived("second", "ab@example.org")
		require.Equal(t, "ab_user_u1", second, "a taken name is suffixed within the maximum")
		require.ErrorIs(t, auth.CheckUsername(ctx, second), iam.ErrUsernameInUse, "the suffixed name passes the policy; only its owner holds it")

		_, err := auth.CreateUser(ctx, iam.NewUser{Email: "short@example.test", Username: "shorty"})
		e := requireIAMCode(t, err, "username_too_short")
		require.Equal(t, map[string]any{"min_length": 8, "max_length": 64}, e.Metadata(), "imports keep the 64-character import ceiling")

		cfg, deps := bareConfig(t)
		cfg.Username = authkit.UsernameConfig{MinLength: 9, MaxLength: 8}
		_, err = newClient(t, cfg, deps)
		require.ErrorContains(t, err, "invalid username policy")
	})
}

// A password reset link dies with any later credential change: a password
// change, a contact change or another reset.
func TestCredentialTransactionsResetGrantsExpireOnCredentialChanges(t *testing.T) {
	for _, change := range []string{"password_change", "contact_change", "other_reset"} {
		t.Run(change, func(t *testing.T) {
			auth, outbox := authtest.New(t, authtest.WithConfig(withAppLinks))
			a := newAPI(t, auth)
			u := authtest.NewUser(t, auth)
			requestReset := func() string {
				t.Helper()
				expect(t, http.StatusAccepted, a.post("/password/reset/request", "", map[string]any{"identifier": u.Email}))
				token := outbox.Last(t, iam.MessagePasswordReset, u.Email).Token
				require.NotEmpty(t, token)
				return token
			}
			stale := requestReset()
			switch change {
			case "password_change":
				token := authtest.SignIn(t, auth, u).AccessToken
				expect(t, http.StatusNoContent, a.post("/user/password", token, map[string]any{"current_password": u.Password, "new_password": "Defender-password-12345"}))
			case "contact_change":
				token := authtest.SignIn(t, auth, u).AccessToken
				next := uniqueEmail("audit-new-email")
				expect(t, http.StatusAccepted, a.do(request{method: http.MethodPut, path: "/me/email", token: token, body: map[string]any{"email": next}}))
				expect(t, http.StatusNoContent, a.post("/verify/confirm", token, map[string]any{"identifier": next, "code": outbox.Last(t, iam.MessageVerification, next).Code}))
			case "other_reset":
				current := requestReset()
				require.NotEqual(t, stale, current)
				expect(t, http.StatusNoContent, a.post("/password/reset/confirm", "", map[string]any{"token": current, "new_password": "Defender-password-12345"}))
			}
			res := a.post("/password/reset/confirm", "", map[string]any{"token": stale, "new_password": "Attacker-password-12345"})
			require.Equal(t, "invalid_link", res.code(), "a credential change invalidates earlier recovery grants: %s", res)
			expect(t, http.StatusUnauthorized, a.post("/password/login", "", map[string]any{"identifier": u.Username, "password": "Attacker-password-12345"}))
		})
	}
}

// One workflow owns manifest parsing, dry run, initial authority, repeat
// names, password seed-once and enforcement, and remote application seeds.
// Repairing an emptied owner set is engine TestBootstrapRepairsAnEmptyOwnerSet.
func TestBootstrapWorkflow(t *testing.T) {
	auth, _ := authtest.New(t)
	a := newAPI(t, auth)
	ctx := t.Context()
	const seeded, rotated = "bootstrap-password-1", "rotated-password-2"
	// passwordIs reports whether the account signs in with password. The
	// password is checked before the owner role's MFA enrollment continuation.
	passwordIs := func(username, password string) bool {
		t.Helper()
		res := a.post("/password/login", "", map[string]string{"identifier": username, "password": password})
		switch {
		case res.status == http.StatusUnauthorized:
			return false
		case res.status == http.StatusOK:
			return true // signed in, or the owner role's MFA enrollment next
		}
		require.FailNow(t, "unexpected sign-in answer", "%s: %s", username, res)
		return false
	}
	manifest, err := authkit.ParseBootstrapManifestYAML([]byte(`users:
 - username: bootstrap-admin
   email: admin@example.test
   email_verified: true
   root_role: root:owner
   metadata: {source: bootstrap-test}
   password: {plaintext: bootstrap-password-1}
`))
	require.NoError(t, err)
	// A role reads only as <persona>:<name>, and a manifest's fields are the
	// iam types' own.
	_, err = authkit.ParseBootstrapManifestYAML([]byte("users:\n - {username: bare, root_role: owner}\n"))
	require.Error(t, err, "a bare role name is refused")
	hash, err := bcrypt.GenerateFromPassword([]byte("seeded-password-1"), bcrypt.MinCost)
	require.NoError(t, err)
	parsed, err := authkit.ParseBootstrapManifestYAML([]byte(`users:
 - username: banned-seed
   ban: {reason: seeded, until: 2099-01-02T03:04:05Z}
   password: {hash: "` + string(hash) + `", algo: bcrypt}
`))
	require.NoError(t, err)
	until := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	require.Equal(t, &iam.BanState{Reason: new("seeded"), Until: &until}, parsed.Users[0].Ban)
	require.Equal(t, iam.HashBcrypt, parsed.Users[0].Password.Algo)
	dry, err := auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{DryRun: true})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{DryRun: true, UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, dry)
	_, err = auth.User(ctx, iam.UserByUsername("bootstrap-admin"))
	require.ErrorIs(t, err, iam.ErrUserNotFound)

	first, err := auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{StartupOnly: true, Name: "first"})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, first)
	user, err := auth.User(ctx, iam.UserByUsername("bootstrap-admin"))
	require.NoError(t, err)
	require.True(t, passwordIs("bootstrap-admin", seeded))
	owner := iam.RootPersona.OwnerRole()
	roleOf := func(subject iam.Subject) iam.Role {
		t.Helper()
		roles, err := auth.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{subject})
		require.NoError(t, err)
		return roles[subject]
	}
	require.Equal(t, owner, roleOf(iam.UserSubject(user.ID)))
	password := rotated
	_, err = auth.UpdateUser(ctx, iam.SystemActor(), user.ID, iam.UserUpdate{Password: &password})
	require.NoError(t, err)

	// Neither the original name nor a different name can replay genesis, even
	// when the new manifest asks to enforce a password or create another owner.
	requested := manifest
	requested.Users = append([]iam.BootstrapManifestUser(nil), manifest.Users...)
	requested.Users[0].Password = &iam.BootstrapUserPassword{Plaintext: seeded, Enforce: true}
	requested.Users = append(requested.Users, iam.BootstrapManifestUser{Username: "unexpected-owner", Email: "unexpected@example.test", RootRole: owner})
	for _, name := range []string{"first", "second", "second"} {
		result, err := auth.ApplyBootstrapManifest(ctx, requested, iam.BootstrapOptions{StartupOnly: true, Name: name})
		require.NoError(t, err)
		require.Equal(t, iam.BootstrapResult{AlreadyApplied: true}, result)
		require.True(t, passwordIs("bootstrap-admin", rotated))
	}
	_, err = auth.User(ctx, iam.UserByUsername("unexpected-owner"))
	require.ErrorIs(t, err, iam.ErrUserNotFound)

	result, err := auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{UsersMatched: 1, PasswordsKept: 1, RootRoleAssignments: 1}, result)
	require.True(t, passwordIs("bootstrap-admin", rotated))
	require.False(t, passwordIs("bootstrap-admin", seeded))
	manifest.Users[0].Password.Enforce = true
	result, err = auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsSet)
	require.True(t, passwordIs("bootstrap-admin", seeded))
	result, err = auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsKept)

	// A repeated manifest cannot appoint another owner while one exists.
	recovery := iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: "recovery-owner", Email: "recovery@example.test", EmailVerified: true, RootRole: owner}}}
	_, err = auth.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.NoError(t, err)
	recoveryUser, err := auth.User(ctx, iam.UserByUsername("recovery-owner"))
	require.NoError(t, err)
	require.NotEqual(t, owner, roleOf(iam.UserSubject(recoveryUser.ID)))
	require.ErrorIs(t, unassign(auth, iam.SystemActor(), iam.RootGroup(), iam.UserSubject(user.ID), owner), iam.ErrLastOwner)

	enabled := true
	app := iam.BootstrapManifestRemoteApplication{Issuer: "https://app.test", JWKSURI: "https://app.test/keys", Enabled: &enabled}
	result, err = auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{app}}, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{RemoteApplications: 1}, result)
	stored, err := auth.RemoteApplication(ctx, iam.AppByIssuer(app.Issuer))
	require.NoError(t, err)
	byID, err := auth.RemoteApplication(ctx, iam.AppByID(stored.ID))
	require.NoError(t, err)
	require.Equal(t, stored, byID, "an application reads the same by id and by issuer")
	require.Equal(t, app.JWKSURI, stored.JWKSURI)
	require.Equal(t, iam.RemoteApplicationModeJWKS, stored.Mode)
	require.True(t, stored.Enabled)
	appRoles, err := auth.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.RemoteApplicationSubject(stored.ID)})
	require.NoError(t, err)
	require.Empty(t, appRoles)
}
