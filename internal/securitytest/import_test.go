package securitytest

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Bootstrap, first-admin and import paths (#399 lane E; audit H3 and the
// bootstrap side of invariant #5): an address or name someone registered
// without proving it never binds an operator's authority to their account,
// and these paths never mark a contact verified on an existing account.

// registerAs registers an unverified password account with a chosen username.
func (h *host) registerAs(email, username string) tokens {
	h.t.Helper()
	resp := h.post("/register", map[string]string{"identifier": email, "username": username, "password": password}, "")
	require.Less(h.t, resp.status, 300, resp.String())
	return session(h.t, resp)
}

func (h *host) rootRole(userID string) iam.Role {
	h.t.Helper()
	roles, err := h.auth.GroupRoles(context.Background(), iam.RootGroup(), []iam.Subject{iam.UserSubject(userID)})
	require.NoError(h.t, err)
	return roles[iam.UserSubject(userID)]
}

// contactState reads what the proof transition guards: verification, the
// password and the account's username.
func (h *host) contactState(userID string) (emailVerified, phoneVerified, hasPassword bool, username string, phone *string) {
	h.t.Helper()
	require.NoError(h.t, h.pool.QueryRow(context.Background(), `SELECT email_verified, phone_verified,
 EXISTS(SELECT 1 FROM user_passwords WHERE user_id=u.id), COALESCE(username::text,''), phone_number FROM users u WHERE id=$1::uuid`, userID).
		Scan(&emailVerified, &phoneVerified, &hasPassword, &username, &phone))
	return
}

// proveEmail proves the address through a password reset and signs in.
func (h *host) proveEmail(email, newPassword string) tokens {
	h.t.Helper()
	require.Less(h.t, h.post("/password/reset/request", map[string]string{"identifier": email}, "").status, 300)
	token := h.mail.last(h.t, `^reset to=`+email+` .* token=(\S+)`)
	resp := h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": newPassword}, "")
	require.Less(h.t, resp.status, 300, resp.String())
	resp = h.post("/password/login", map[string]string{"identifier": email, "password": newPassword}, "")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	return session(h.t, resp)
}

// TestSecurityBootstrapNeverAdoptsSquatters (H3): a manifest naming an address
// or username someone pre-registered is refused and leaves that account
// without the role and without proven contacts.
func TestSecurityBootstrapNeverAdoptsSquatters(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	apply := func(users ...iam.BootstrapManifestUser) (iam.BootstrapResult, error) {
		return h.auth.ApplyBootstrapManifest(ctx, iam.OperatorActor(), iam.BootstrapManifest{Users: users}, iam.BootstrapOptions{})
	}
	requireUntouched := func(t *testing.T, userID string) {
		t.Helper()
		require.Empty(t, h.rootRole(userID), "the squatter received the manifest's role")
		emailVerified, _, hasPassword, _, _ := h.contactState(userID)
		require.False(t, emailVerified, "bootstrap marked the squatter's address verified")
		require.True(t, hasPassword, "the squatter's own credential was replaced")
	}

	t.Run("squatted username and unverified email", func(t *testing.T) {
		name, email := unique("ops"), unique("ops")+"@security.test"
		h.registerAs(email, name)
		squatter := h.userID(email)
		_, err := apply(iam.BootstrapManifestUser{Username: name, Email: email, EmailVerified: true, RootRole: "admin"})
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		requireUntouched(t, squatter)
	})

	t.Run("squatted username with a fresh address", func(t *testing.T) {
		name := unique("opsname")
		h.registerAs(unique("other")+"@security.test", name)
		squatter := h.userIDByName(name)
		fresh := unique("fresh") + "@security.test"
		_, err := apply(iam.BootstrapManifestUser{Username: name, Email: fresh, EmailVerified: true, RootRole: "admin"})
		require.ErrorIs(t, err, iam.ErrUsernameInUse)
		requireUntouched(t, squatter)
		require.False(t, h.emailTaken(fresh), "the refused apply left an account behind")
	})

	t.Run("username only never binds", func(t *testing.T) {
		name := unique("opsbare")
		h.registerAs(unique("bare")+"@security.test", name)
		squatter := h.userIDByName(name)
		_, err := apply(iam.BootstrapManifestUser{Username: name, RootRole: "admin"})
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		requireUntouched(t, squatter)
		// Nothing to change is not an adoption: the apply stays idempotent.
		res, err := apply(iam.BootstrapManifestUser{Username: name})
		require.NoError(t, err)
		require.Equal(t, 1, res.UsersMatched)
		requireUntouched(t, squatter)
	})

	aliasOf := func(t *testing.T) (alias, squatter string) {
		t.Helper()
		alias = unique("opsalias")
		s := h.registerAs(unique("alias")+"@security.test", alias)
		squatter = h.userIDByName(alias)
		resp := h.do(request{method: http.MethodPatch, path: "/user/username", body: map[string]string{"username": unique("renamed")}, token: s.AccessToken})
		require.Less(t, resp.status, 300, resp.String())
		return alias, squatter
	}
	t.Run("live alias", func(t *testing.T) {
		alias, squatter := aliasOf(t)
		_, err := apply(iam.BootstrapManifestUser{Username: alias, Email: unique("aliasfresh") + "@security.test", EmailVerified: true, RootRole: "admin"})
		require.ErrorIs(t, err, iam.ErrUsernameInUse)
		requireUntouched(t, squatter)
		_, err = apply(iam.BootstrapManifestUser{Username: alias, RootRole: "admin"})
		require.ErrorIs(t, err, iam.ErrUsernameInUse)
		requireUntouched(t, squatter)
	})
	t.Run("expired alias", func(t *testing.T) {
		alias, squatter := aliasOf(t)
		_, err := h.pool.Exec(ctx, `UPDATE name_claims SET expires_at=now()-interval '1 minute' WHERE owner_kind='user' AND name=lower($1) AND NOT canonical`, alias)
		require.NoError(t, err)
		email := unique("expired") + "@security.test"
		res, err := apply(iam.BootstrapManifestUser{Username: alias, Email: email, EmailVerified: true, RootRole: "admin"})
		require.NoError(t, err)
		require.Equal(t, 1, res.UsersCreated)
		requireUntouched(t, squatter)
		fresh := h.userID(email)
		require.NotEqual(t, squatter, fresh)
		require.Equal(t, iam.Role("admin"), h.rootRole(fresh))
	})

	t.Run("control: a verified address binds, and the account keeps its identity", func(t *testing.T) {
		owner := h.newAccount("bound")
		h.enrollEmail2FA(owner) // admin edits accounts, which needs MFA
		phone := "+1555" + uniqueDigits(7)
		res, err := apply(iam.BootstrapManifestUser{Username: unique("manifestname"), Email: owner.email, Phone: phone, PhoneVerified: true, RootRole: "admin",
			Password: &iam.BootstrapUserPassword{Plaintext: "Manifest-seeded-passphrase-1"}})
		require.NoError(t, err)
		require.Equal(t, iam.BootstrapResult{UsersMatched: 1, PasswordsKept: 1, RootRoleAssignments: 1}, res)
		require.Equal(t, iam.Role("admin"), h.rootRole(owner.id))
		_, phoneVerified, _, username, storedPhone := h.contactState(owner.id)
		require.Equal(t, owner.username, username)
		require.Nil(t, storedPhone, "bootstrap wrote a contact onto an existing account")
		require.False(t, phoneVerified)
		h.login(owner)
	})

	t.Run("non-operator actors are refused", func(t *testing.T) {
		admin := h.newAccount("bootadmin")
		h.grant(iam.RootGroup(), admin, "admin")
		for _, actor := range []iam.Actor{{}, iam.UserActor(admin.id)} {
			_, err := h.auth.ApplyBootstrapManifest(ctx, actor, iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: unique("x"), RootRole: "admin"}}}, iam.BootstrapOptions{})
			require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
		}
	})
}

// TestSecurityEnsureUserRole: the README's first-admin call is idempotent on
// every boot, never adopts a pre-registered account, and the account it
// creates can only be entered by proving its address.
func TestSecurityEnsureUserRole(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	op, root := iam.OperatorActor(), iam.RootGroup()

	t.Run("creates a credential-less account, then re-runs as a no-op", func(t *testing.T) {
		email := unique("firstadmin") + "@security.test"
		first, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "moderator")
		require.NoError(t, err)
		require.False(t, first.EmailVerified)
		emailVerified, _, hasPassword, _, _ := h.contactState(first.ID)
		require.False(t, emailVerified)
		require.False(t, hasPassword)
		require.Equal(t, iam.Role("moderator"), h.rootRole(first.ID))
		again, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "moderator")
		require.NoError(t, err)
		require.Equal(t, first.ID, again.ID)

		// Unproven, the account gets nothing more.
		_, err = h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "admin")
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		require.Equal(t, iam.Role("moderator"), h.rootRole(first.ID))
		login := h.post("/password/login", map[string]string{"identifier": email, "password": password}, "")
		require.Equal(t, http.StatusUnauthorized, login.status, login.String())

		// Proving the address is the one way in, and it verifies the address.
		h.proveEmail(email, password)
		emailVerified, _, _, _, _ = h.contactState(first.ID)
		require.True(t, emailVerified)
		// admin edits accounts, which needs MFA.
		_, err = h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "admin")
		require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
		h.enrollEmail2FA(account{id: first.ID, email: email})
		promoted, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "admin")
		require.NoError(t, err)
		require.Equal(t, first.ID, promoted.ID)
		require.Equal(t, iam.Role("admin"), h.rootRole(first.ID))
		// A held role covering the requested one is kept, never downgraded.
		_, err = h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "moderator")
		require.NoError(t, err)
		require.Equal(t, iam.Role("admin"), h.rootRole(first.ID))
	})

	t.Run("refuses a pre-registered account", func(t *testing.T) {
		email := unique("squatadmin") + "@security.test"
		h.register(email)
		squatter := h.userID(email)
		_, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(email), "admin")
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		require.Empty(t, h.rootRole(squatter))
		emailVerified, _, hasPassword, _, _ := h.contactState(squatter)
		require.False(t, emailVerified)
		require.True(t, hasPassword)
	})

	t.Run("a username never finds an account", func(t *testing.T) {
		name := unique("namedadmin")
		h.registerAs(unique("named")+"@security.test", name)
		_, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByUsername(name), "admin")
		require.Error(t, err)
		require.Empty(t, h.rootRole(h.userIDByName(name)))
	})

	t.Run("a verified account or an explicit id binds", func(t *testing.T) {
		verified := h.newAccount("verifiedadmin")
		h.enrollEmail2FA(verified)
		u, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(verified.email), "admin")
		require.NoError(t, err)
		require.Equal(t, verified.id, u.ID)
		require.Equal(t, iam.Role("admin"), h.rootRole(verified.id))

		email := unique("byid") + "@security.test"
		h.register(email)
		named := h.userID(email)
		_, err = h.auth.EnsureUserRole(ctx, op, root, iam.UserByID(named), "moderator")
		require.NoError(t, err)
		require.Equal(t, iam.Role("moderator"), h.rootRole(named))
		emailVerified, _, _, _, _ := h.contactState(named)
		require.False(t, emailVerified, "EnsureUserRole marked an address verified")
		_, err = h.auth.EnsureUserRole(ctx, op, root, iam.UserByID(uuid.NewString()), "moderator")
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	})

	t.Run("a covering role is kept", func(t *testing.T) {
		owner := h.newAccount("keptowner")
		h.grant(root, owner, "superadmin")
		_, err := h.auth.EnsureUserRole(ctx, op, root, iam.UserByEmail(owner.email), "admin")
		require.NoError(t, err)
		require.Equal(t, iam.Role("superadmin"), h.rootRole(owner.id))
	})

	t.Run("non-operator actors are refused", func(t *testing.T) {
		admin := h.newAccount("ensureadmin")
		h.grant(root, admin, "superadmin")
		for _, actor := range []iam.Actor{{}, iam.UserActor(admin.id)} {
			_, err := h.auth.EnsureUserRole(ctx, actor, root, iam.UserByEmail(unique("nobody")+"@security.test"), "moderator")
			require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
		}
	})
}

// TestSecurityImportUsers: every row reports its account, hashes are
// validated, bcrypt imports verify and rehash, and a merge only reaches an
// account bound by id or a verified address.
func TestSecurityImportUsers(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	op := iam.OperatorActor()
	raw, err := bcrypt.GenerateFromPassword([]byte("Imported-legacy-pass-1"), bcrypt.MinCost)
	require.NoError(t, err)
	bcryptHash := string(raw)
	a := iam.ImportUser{Email: unique("impa") + "@security.test", Username: unique("impa"), EmailVerified: true, PasswordHash: bcryptHash, HashAlgo: "bcrypt"}
	b := iam.ImportUser{Phone: "+1555" + uniqueDigits(7), Username: unique("impb")}
	legacy := iam.ImportUser{Email: unique("impl") + "@security.test", Username: unique("impl"), PasswordHash: "$1$legacy$md5crypt", HashAlgo: iam.HashAlgoLegacyResetRequired}
	declared := iam.ImportUser{ID: uuid.NewString(), Email: unique("impd") + "@security.test", Username: unique("impd")}
	rows := []iam.ImportUser{
		a, b, legacy, declared,
		{Email: unique("bad") + "@security.test", Username: unique("impbad"), PasswordHash: "not-a-hash", HashAlgo: "bcrypt"},
		{Email: a.Email, Username: unique("impdup")},
		{Email: legacy.Email, Username: b.Username},
	}
	res, err := h.auth.ImportUsers(ctx, op, rows, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 4, res.Inserted)
	require.Equal(t, iam.ImportRejected, res.Rows[4].Status)
	require.Equal(t, "invalid_password_hash", res.Rows[4].Reason)
	require.Equal(t, iam.ImportRow{Index: 5, UserID: res.Rows[0].UserID, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportSkipped, Reason: "duplicate_in_batch"}, res.Rows[5])
	require.Equal(t, iam.ImportRow{Index: 6, Status: iam.ImportRejected, Reason: "identifier_conflict"}, res.Rows[6])
	require.Equal(t, declared.ID, res.Rows[3].UserID)
	ids := []string{res.Rows[0].UserID, res.Rows[1].UserID, res.Rows[2].UserID, res.Rows[3].UserID}

	// A re-run reports the same accounts.
	again, err := h.auth.ImportUsers(ctx, op, rows[:4], iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 4, again.Skipped)
	for i, match := range []iam.ImportMatch{iam.ImportMatchEmail, iam.ImportMatchPhone, iam.ImportMatchEmail, iam.ImportMatchID} {
		require.Equal(t, iam.ImportRow{Index: i, UserID: ids[i], MatchedBy: match, Status: iam.ImportSkipped, Reason: "already_exists"}, again.Rows[i])
	}

	t.Run("legacy hashes", func(t *testing.T) {
		resp := h.post("/password/login", map[string]string{"identifier": a.Email, "password": "Imported-legacy-pass-1"}, "")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		var algo string
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT hash_algo FROM user_passwords WHERE user_id=$1::uuid`, ids[0]).Scan(&algo))
		require.Equal(t, "argon2id", algo, "a verified bcrypt password was not rehashed")
		resp = h.post("/password/login", map[string]string{"identifier": legacy.Email, "password": "anything-at-all-1"}, "")
		require.Equal(t, string(errmodel.CodePasswordResetRequired), resp.errorCode(), resp.String())
	})

	t.Run("merge binds only by id or a verified address", func(t *testing.T) {
		squat := unique("impsquat") + "@security.test"
		h.register(squat)
		squatter := h.userID(squat)
		owner := h.newAccount("impowner")
		merge := iam.ImportOptions{OnConflict: iam.ImportMerge}
		out, err := h.auth.ImportUsers(ctx, op, []iam.ImportUser{
			{Email: squat, EmailVerified: true, Username: unique("impx"), Metadata: map[string]any{"vip": true}, PasswordHash: bcryptHash, HashAlgo: "bcrypt"},
			{ID: ids[1], Username: b.Username, Metadata: map[string]any{"legacy_id": 7}, PasswordHash: bcryptHash, HashAlgo: "bcrypt"},
			{Email: owner.email, EmailVerified: true, Username: unique("impy"), Metadata: map[string]any{"legacy_id": 8}, PasswordHash: bcryptHash, HashAlgo: "bcrypt"},
		}, merge)
		require.NoError(t, err)
		require.Equal(t, iam.ImportRow{Index: 0, UserID: squatter, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportSkipped, Reason: "unbound_match"}, out.Rows[0])
		require.Equal(t, iam.ImportRow{Index: 1, UserID: ids[1], MatchedBy: iam.ImportMatchID, Status: iam.ImportMerged}, out.Rows[1])
		require.Equal(t, iam.ImportRow{Index: 2, UserID: owner.id, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportMerged}, out.Rows[2])

		var vip bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT metadata ? 'vip' FROM users WHERE id=$1::uuid`, squatter).Scan(&vip))
		require.False(t, vip, "an unverified address bound an import row")
		emailVerified, _, _, _, _ := h.contactState(squatter)
		require.False(t, emailVerified)
		var legacyID string
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT metadata->>'legacy_id' FROM users WHERE id=$1::uuid`, ids[1]).Scan(&legacyID))
		require.Equal(t, "7", legacyID)
		_, phoneVerified, hasPassword, _, _ := h.contactState(ids[1])
		require.True(t, hasPassword, "a merge by id did not fill the missing password")
		require.False(t, phoneVerified)
		h.login(owner) // the account's own password survives a merge
	})

	t.Run("non-operator actors are refused", func(t *testing.T) {
		user := h.newAccount("impuser")
		_, err := h.auth.ImportUsers(ctx, iam.UserActor(user.id), []iam.ImportUser{{Username: unique("x")}}, iam.ImportOptions{})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	})
}

// TestSecurityImportSolanaLinks: imported wallets are reservations, never
// login methods, and never move between accounts.
func TestSecurityImportSolanaLinks(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(func(c *authkit.Config) { c.SolanaNetwork = "devnet" }))
	ctx := context.Background()
	one, two := h.newAccount("walletone"), h.newAccount("wallettwo")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	address := base58.Encode(key)
	link := iam.ImportSolanaLink{UserID: one.id, Address: address, Source: "legacy", SourceID: "1"}
	res, err := h.auth.ImportSolanaLinks(ctx, iam.OperatorActor(), []iam.ImportSolanaLink{
		link,
		link,
		{UserID: two.id, Address: address, Source: "legacy", SourceID: "2"},
		{UserID: two.id, Address: "not-an-address", Source: "legacy", SourceID: "3"},
	})
	require.NoError(t, err)
	require.Equal(t, iam.ImportSolanaLinksResult{Rows: []iam.ImportSolanaLinkRow{
		{Index: 0, UserID: one.id, Address: address, Status: iam.ImportInserted},
		{Index: 1, UserID: one.id, Address: address, Status: iam.ImportSkipped, Reason: "already_imported"},
		{Index: 2, UserID: two.id, Address: address, Status: iam.ImportRejected, Reason: "address_owned_by_other_user"},
		{Index: 3, UserID: two.id, Address: "not-an-address", Status: iam.ImportRejected, Reason: "invalid_address"},
	}, Inserted: 1, Skipped: 1, Rejected: 2}, res)
	var verified bool
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM user_providers WHERE subject=$1`, address).Scan(&verified))
	require.False(t, verified, "an imported wallet became a login method")
	_, err = h.auth.ImportSolanaLinks(ctx, iam.UserActor(one.id), []iam.ImportSolanaLink{link})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
}

// TestSecurityLinkProvider: an operator-linked identity signs in to exactly
// the account it names; nobody else can link.
func TestSecurityLinkProvider(t *testing.T) {
	provider := &stubProvider{name: "opidp"}
	provider.identity.Subject = unique("opsub")
	h := newHost(t, withHTTP(generousLimits), withProviders(provider))
	ctx := context.Background()
	owner := h.newAccount("linked")
	l := iam.ProviderLink{Issuer: provider.Issuer(), Provider: provider.Name(), Subject: provider.identity.Subject}
	require.ErrorIs(t, h.auth.LinkProvider(ctx, iam.UserActor(owner.id), owner.id, l), iam.ErrInsufficientAuthority)
	require.ErrorIs(t, h.auth.LinkProvider(ctx, iam.OperatorActor(), uuid.NewString(), l), iam.ErrUserNotFound)
	require.NoError(t, h.auth.LinkProvider(ctx, iam.OperatorActor(), owner.id, l))
	var users int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&users))
	resp := h.providerCallback(provider.name)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var linkedTo string
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT user_id::text FROM user_providers WHERE subject=$1`, l.Subject).Scan(&linkedTo))
	require.Equal(t, owner.id, linkedTo)
	var after int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&after))
	require.Equal(t, users, after, "the provider login created an account instead of using the linked one")
	other := h.newAccount("linkedother")
	require.ErrorIs(t, h.auth.LinkProvider(ctx, iam.OperatorActor(), other.id, l), errmodel.ErrProviderAlreadyLinked)
}

func (h *host) userIDByName(username string) string {
	h.t.Helper()
	var id string
	require.NoError(h.t, h.pool.QueryRow(context.Background(), `SELECT id::text FROM users WHERE username=$1`, username).Scan(&id))
	return id
}

func (h *host) emailTaken(email string) bool {
	h.t.Helper()
	var taken bool
	require.NoError(h.t, h.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&taken))
	return taken
}

func uniqueDigits(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = '0' + b[i]%10
	}
	return string(b)
}
