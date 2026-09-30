package securitytest

import (
	"context"
	"crypto/rand"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Bootstrap, first-admin and import paths (#399 lane E; audit H3 and the
// bootstrap side of invariant #5): an address or name someone registered
// without proving it never binds the system's authority to their account,
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
	token := h.mail.Last(h.t, authtest.PasswordReset, email).Token
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
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	apply := func(users ...iam.BootstrapManifestUser) (iam.BootstrapResult, error) {
		return h.auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{Users: users}, iam.BootstrapOptions{})
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
		_, err := apply(iam.BootstrapManifestUser{Username: name, Email: email, EmailVerified: true, RootRole: h.role(iam.RootPersona, "admin")})
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		requireUntouched(t, squatter)
	})

	t.Run("squatted username with a fresh address", func(t *testing.T) {
		name := unique("opsname")
		h.registerAs(unique("other")+"@security.test", name)
		squatter := h.userIDByName(name)
		fresh := unique("fresh") + "@security.test"
		_, err := apply(iam.BootstrapManifestUser{Username: name, Email: fresh, EmailVerified: true, RootRole: h.role(iam.RootPersona, "admin")})
		require.ErrorIs(t, err, iam.ErrUsernameInUse)
		requireUntouched(t, squatter)
		require.False(t, h.emailTaken(fresh), "the refused apply left an account behind")
	})

	t.Run("username only never binds", func(t *testing.T) {
		name := unique("opsbare")
		h.registerAs(unique("bare")+"@security.test", name)
		squatter := h.userIDByName(name)
		_, err := apply(iam.BootstrapManifestUser{Username: name, RootRole: h.role(iam.RootPersona, "admin")})
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
		_, err := apply(iam.BootstrapManifestUser{Username: alias, Email: unique("aliasfresh") + "@security.test", EmailVerified: true, RootRole: h.role(iam.RootPersona, "admin")})
		require.ErrorIs(t, err, iam.ErrUsernameInUse)
		requireUntouched(t, squatter)
		_, err = apply(iam.BootstrapManifestUser{Username: alias, RootRole: h.role(iam.RootPersona, "admin")})
		require.ErrorIs(t, err, iam.ErrUsernameInUse)
		requireUntouched(t, squatter)
	})
	t.Run("expired alias", func(t *testing.T) {
		alias, squatter := aliasOf(t)
		_, err := h.pool.Exec(ctx, `UPDATE name_claims SET expires_at=now()-interval '1 minute' WHERE owner_kind='user' AND name=lower($1) AND NOT canonical`, alias)
		require.NoError(t, err)
		email := unique("expired") + "@security.test"
		res, err := apply(iam.BootstrapManifestUser{Username: alias, Email: email, EmailVerified: true, RootRole: h.role(iam.RootPersona, "admin")})
		require.NoError(t, err)
		require.Equal(t, 1, res.UsersCreated)
		requireUntouched(t, squatter)
		fresh := h.userID(email)
		require.NotEqual(t, squatter, fresh)
		require.Equal(t, h.role(iam.RootPersona, "admin"), h.rootRole(fresh))
	})

	t.Run("control: a verified address binds, and the account keeps its identity", func(t *testing.T) {
		owner := h.newAccount("bound")
		h.enrollEmail2FA(owner) // admin edits accounts, which needs MFA
		phone := "+1555" + uniqueDigits(7)
		res, err := apply(iam.BootstrapManifestUser{Username: unique("manifestname"), Email: owner.email, Phone: phone, PhoneVerified: true, RootRole: h.role(iam.RootPersona, "admin"),
			Password: &iam.BootstrapUserPassword{Plaintext: "Manifest-seeded-passphrase-1"}})
		require.NoError(t, err)
		require.Equal(t, iam.BootstrapResult{UsersMatched: 1, PasswordsKept: 1, RootRoleAssignments: 1}, res)
		require.Equal(t, h.role(iam.RootPersona, "admin"), h.rootRole(owner.id))
		_, phoneVerified, _, username, storedPhone := h.contactState(owner.id)
		require.Equal(t, owner.username, username)
		require.Nil(t, storedPhone, "bootstrap wrote a contact onto an existing account")
		require.False(t, phoneVerified)
		h.login(owner)
	})
}

// TestSecurityEnsureUserRole: the README's first-admin call is idempotent on
// every boot, never adopts a pre-registered account, and the account it
// creates can only be entered by proving its address.
func TestSecurityEnsureUserRole(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	root := iam.RootGroup()

	t.Run("creates a credential-less account, then re-runs as a no-op", func(t *testing.T) {
		email := unique("firstadmin") + "@security.test"
		first, err := h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "moderator"))
		require.NoError(t, err)
		require.False(t, first.EmailVerified)
		emailVerified, _, hasPassword, _, _ := h.contactState(first.ID)
		require.False(t, emailVerified)
		require.False(t, hasPassword)
		require.Equal(t, h.role(iam.RootPersona, "moderator"), h.rootRole(first.ID))
		again, err := h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "moderator"))
		require.NoError(t, err)
		require.Equal(t, first.ID, again.ID)

		// Unproven, the account gets nothing more.
		_, err = h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "admin"))
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		require.Equal(t, h.role(iam.RootPersona, "moderator"), h.rootRole(first.ID))
		login := h.post("/password/login", map[string]string{"identifier": email, "password": password}, "")
		require.Equal(t, http.StatusUnauthorized, login.status, login.String())

		// Proving the address is the one way in, and it verifies the address.
		h.proveEmail(email, password)
		emailVerified, _, _, _, _ = h.contactState(first.ID)
		require.True(t, emailVerified)
		// admin edits accounts, which needs MFA.
		_, err = h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "admin"))
		require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
		h.enrollEmail2FA(account{id: first.ID, email: email})
		promoted, err := h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "admin"))
		require.NoError(t, err)
		require.Equal(t, first.ID, promoted.ID)
		require.Equal(t, h.role(iam.RootPersona, "admin"), h.rootRole(first.ID))
		// A held role covering the requested one is kept, never downgraded.
		_, err = h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "moderator"))
		require.NoError(t, err)
		require.Equal(t, h.role(iam.RootPersona, "admin"), h.rootRole(first.ID))
	})

	t.Run("refuses a pre-registered account", func(t *testing.T) {
		email := unique("squatadmin") + "@security.test"
		h.register(email)
		squatter := h.userID(email)
		_, err := h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(email), h.role(iam.RootPersona, "admin"))
		require.ErrorIs(t, err, iam.ErrContactNotVerified)
		require.Empty(t, h.rootRole(squatter))
		emailVerified, _, hasPassword, _, _ := h.contactState(squatter)
		require.False(t, emailVerified)
		require.True(t, hasPassword)
	})

	t.Run("a username never finds an account", func(t *testing.T) {
		name := unique("namedadmin")
		h.registerAs(unique("named")+"@security.test", name)
		_, err := h.auth.EnsureUserRole(ctx, root, iam.UserByUsername(name), h.role(iam.RootPersona, "admin"))
		require.Error(t, err)
		require.Empty(t, h.rootRole(h.userIDByName(name)))
	})

	t.Run("a verified account or an explicit id binds", func(t *testing.T) {
		verified := h.newAccount("verifiedadmin")
		h.enrollEmail2FA(verified)
		u, err := h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(verified.email), h.role(iam.RootPersona, "admin"))
		require.NoError(t, err)
		require.Equal(t, verified.id, u.ID)
		require.Equal(t, h.role(iam.RootPersona, "admin"), h.rootRole(verified.id))

		email := unique("byid") + "@security.test"
		h.register(email)
		named := h.userID(email)
		_, err = h.auth.EnsureUserRole(ctx, root, iam.UserByID(named), h.role(iam.RootPersona, "moderator"))
		require.NoError(t, err)
		require.Equal(t, h.role(iam.RootPersona, "moderator"), h.rootRole(named))
		emailVerified, _, _, _, _ := h.contactState(named)
		require.False(t, emailVerified, "EnsureUserRole marked an address verified")
		_, err = h.auth.EnsureUserRole(ctx, root, iam.UserByID(uuid.NewString()), h.role(iam.RootPersona, "moderator"))
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	})

	t.Run("a covering role is kept", func(t *testing.T) {
		owner := h.newAccount("keptowner")
		h.grant(root, owner, "superadmin")
		_, err := h.auth.EnsureUserRole(ctx, root, iam.UserByEmail(owner.email), h.role(iam.RootPersona, "admin"))
		require.NoError(t, err)
		require.Equal(t, h.role(iam.RootPersona, "superadmin"), h.rootRole(owner.id))
	})
}

// TestSecurityImportUsers: every row reports its account, hashes are
// validated, bcrypt imports verify and rehash, and a merge only reaches an
// account bound by id or a verified address.
func TestSecurityImportUsers(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	raw, err := bcrypt.GenerateFromPassword([]byte("Imported-legacy-pass-1"), bcrypt.MinCost)
	require.NoError(t, err)
	bcryptHash := string(raw)
	a := iam.ImportUser{Email: unique("impa") + "@security.test", Username: unique("impa"), EmailVerified: true, PasswordHash: &iam.PasswordHash{Hash: bcryptHash, Algo: iam.HashBcrypt}}
	b := iam.ImportUser{Phone: "+1555" + uniqueDigits(7), Username: unique("impb")}
	legacy := iam.ImportUser{Email: unique("impl") + "@security.test", Username: unique("impl"), PasswordHash: &iam.PasswordHash{Hash: "$1$legacy$md5crypt", Algo: iam.HashLegacyResetRequired}}
	declared := iam.ImportUser{ID: uuid.NewString(), Email: unique("impd") + "@security.test", Username: unique("impd")}
	rows := []iam.ImportUser{
		a, b, legacy, declared,
		{Email: unique("bad") + "@security.test", Username: unique("impbad"), PasswordHash: &iam.PasswordHash{Hash: "not-a-hash", Algo: iam.HashBcrypt}},
		{Email: a.Email, Username: unique("impdup")},
		{Email: legacy.Email, Username: b.Username},
	}
	res, err := h.auth.ImportUsers(ctx, rows, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 4, res.Inserted)
	require.Equal(t, iam.ImportRejected, res.Rows[4].Status)
	require.Equal(t, iam.ImportInvalidPasswordHash, res.Rows[4].Reason)
	require.Equal(t, iam.ImportRow{Index: 5, UserID: res.Rows[0].UserID, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportSkipped, Reason: "duplicate_in_batch"}, res.Rows[5])
	require.Equal(t, iam.ImportRow{Index: 6, Status: iam.ImportRejected, Reason: "identifier_conflict"}, res.Rows[6])
	require.Equal(t, declared.ID, res.Rows[3].UserID)
	ids := []string{res.Rows[0].UserID, res.Rows[1].UserID, res.Rows[2].UserID, res.Rows[3].UserID}

	// A re-run reports the same accounts.
	again, err := h.auth.ImportUsers(ctx, rows[:4], iam.ImportOptions{})
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
		out, err := h.auth.ImportUsers(ctx, []iam.ImportUser{
			{Email: squat, EmailVerified: true, Username: unique("impx"), Metadata: map[string]any{"vip": true}, PasswordHash: &iam.PasswordHash{Hash: bcryptHash, Algo: iam.HashBcrypt}},
			{ID: ids[1], Username: b.Username, Metadata: map[string]any{"legacy_id": 7}, PasswordHash: &iam.PasswordHash{Hash: bcryptHash, Algo: iam.HashBcrypt}},
			{Email: owner.email, EmailVerified: true, Username: unique("impy"), Metadata: map[string]any{"legacy_id": 8}, PasswordHash: &iam.PasswordHash{Hash: bcryptHash, Algo: iam.HashBcrypt}},
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
}

// TestSecurityImportSolanaLinks: imported wallets are reservations, never
// login methods, and never move between accounts.
func TestSecurityImportSolanaLinks(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) { c.SolanaNetwork = "devnet" }))
	ctx := context.Background()
	one, two := h.newAccount("walletone"), h.newAccount("wallettwo")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	address := base58.Encode(key)
	link := iam.ImportSolanaLink{UserID: one.id, Address: address, Source: "legacy", SourceID: "1"}
	res, err := h.auth.ImportSolanaLinks(ctx, []iam.ImportSolanaLink{
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
}

// TestSecurityLinkProvider: a host-linked identity signs in to exactly the
// account it names, and never moves to another.
func TestSecurityLinkProvider(t *testing.T) {
	idp := testidp.New(t)
	provider := idp.OAuth2("opidp")
	h := newHost(t, withHTTP(generousLimits), withProviders(provider))
	ctx := context.Background()
	owner := h.newAccount("linked")
	l := iam.ProviderLink{Issuer: provider.Issuer(), Provider: provider.Name(), Subject: unique("opsub")}
	require.ErrorIs(t, h.auth.LinkProvider(ctx, uuid.NewString(), l), iam.ErrUserNotFound)
	require.NoError(t, h.auth.LinkProvider(ctx, owner.id, l))
	var users int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&users))
	resp := h.providerCallback(idp, provider.Name(), testidp.Identity{Subject: l.Subject})
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var linkedTo string
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT user_id::text FROM user_providers WHERE subject=$1`, l.Subject).Scan(&linkedTo))
	require.Equal(t, owner.id, linkedTo)
	var after int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&after))
	require.Equal(t, users, after, "the provider login created an account instead of using the linked one")
	other := h.newAccount("linkedother")
	require.ErrorIs(t, h.auth.LinkProvider(ctx, other.id, l), errmodel.ErrProviderAlreadyLinked)
}

// TestSecurityImportProviders: an imported provider identity signs in to
// exactly the imported account, and an import never binds an identity another
// account holds, or one another row of the batch names. A merge links
// identities only for a row bound by id or a contact verified on both sides.
func TestSecurityImportProviders(t *testing.T) {
	idp := testidp.New(t)
	provider := idp.OAuth2("impidp")
	h := newHost(t, withHTTP(generousLimits), withProviders(provider))
	ctx := context.Background()
	link := func(prefix string) iam.ProviderLink {
		return iam.ProviderLink{Issuer: provider.Issuer(), Provider: provider.Name(), Subject: unique(prefix)}
	}
	row := func(prefix string, links ...iam.ProviderLink) iam.ImportUser {
		name := unique(prefix)
		return iam.ImportUser{Email: name + "@security.test", EmailVerified: true, Username: name, Providers: links}
	}
	holder := h.newAccount("impholder")
	held, fresh, skipped := link("heldsub"), link("freshsub"), link("skipsub")
	require.NoError(t, h.auth.LinkProvider(ctx, holder.id, held))
	exists := row("impexists", skipped)
	exists.Email = holder.email
	rows := []iam.ImportUser{
		row("impfresh", fresh),
		row("impheld", held),
		row("impsame", fresh),
		row("impwallet", iam.ProviderLink{Issuer: "solana:devnet", Provider: "solana", Subject: "wallet"}),
		row("imptwice", link("twicea"), link("twiceb")),
		row("impblank", iam.ProviderLink{Issuer: provider.Issuer()}),
		exists,
	}
	res, err := h.auth.ImportUsers(ctx, rows, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.ImportInserted, res.Rows[0].Status)
	for i, reason := range map[int]iam.ImportReason{1: "provider_already_linked", 2: "provider_already_linked", 3: "invalid_provider", 4: "invalid_provider", 5: "invalid_provider"} {
		require.Equal(t, iam.ImportRow{Index: i, Status: iam.ImportRejected, Reason: reason}, res.Rows[i])
		require.False(t, h.emailTaken(rows[i].Email), "a rejected row left an account behind")
	}
	require.Equal(t, iam.ImportRow{Index: 6, UserID: holder.id, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportSkipped, Reason: "already_exists"}, res.Rows[6])
	require.Equal(t, holder.id, h.providerOwner(held.Subject), "an import moved a linked identity")
	require.Empty(t, h.providerOwner(skipped.Subject), "a skipped row linked an identity")
	require.Equal(t, res.Rows[0].UserID, h.providerOwner(fresh.Subject))

	resp := h.providerCallback(idp, provider.Name(), testidp.Identity{Subject: fresh.Subject})
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	require.Equal(t, res.Rows[0].UserID, h.meID(session(t, resp).AccessToken))

	t.Run("merge", func(t *testing.T) {
		merge := iam.ImportOptions{OnConflict: iam.ImportMerge}
		byID, byEmail, byBoth := link("mergeid"), link("mergeemail"), link("mergeboth")
		target, other, both := h.newAccount("impmerge"), h.newAccount("impmergeother"), h.newAccount("impmergeboth")
		out, err := h.auth.ImportUsers(ctx, []iam.ImportUser{
			{ID: target.id, Username: target.username, Providers: []iam.ProviderLink{byID}},
			{Email: other.email, Username: unique("impmergex"), Providers: []iam.ProviderLink{byEmail}},
			{ID: other.id, Username: other.username, Providers: []iam.ProviderLink{held}, Metadata: map[string]any{"stolen": true}},
			{Email: both.email, EmailVerified: true, Username: unique("impmergey"), Providers: []iam.ProviderLink{byBoth}},
		}, merge)
		require.NoError(t, err)
		require.Equal(t, iam.ImportRow{Index: 0, UserID: target.id, MatchedBy: iam.ImportMatchID, Status: iam.ImportMerged}, out.Rows[0])
		require.Equal(t, iam.ImportRow{Index: 1, UserID: other.id, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportMerged}, out.Rows[1])
		require.Equal(t, iam.ImportRow{Index: 2, Status: iam.ImportRejected, Reason: "provider_already_linked"}, out.Rows[2])
		require.Equal(t, iam.ImportRow{Index: 3, UserID: both.id, MatchedBy: iam.ImportMatchEmail, Status: iam.ImportMerged}, out.Rows[3])
		require.Equal(t, target.id, h.providerOwner(byID.Subject))
		require.Empty(t, h.providerOwner(byEmail.Subject), "a row not proven by id or a verified contact linked an identity")
		require.Equal(t, holder.id, h.providerOwner(held.Subject))
		require.Equal(t, both.id, h.providerOwner(byBoth.Subject))
		var stolen bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT metadata ? 'stolen' FROM users WHERE id=$1::uuid`, other.id).Scan(&stolen))
		require.False(t, stolen, "a rejected merge kept part of its row")

		again, err := h.auth.ImportUsers(ctx, []iam.ImportUser{{ID: target.id, Username: target.username, Providers: []iam.ProviderLink{link("mergesecond")}}}, merge)
		require.NoError(t, err)
		require.Equal(t, iam.ImportRow{Index: 0, Status: iam.ImportRejected, Reason: "provider_change_requires_unlink"}, again.Rows[0])
	})
}

// TestSecurityImportedDeletionLifecycle: an imported deleted account is
// what the system's DeleteUsers leaves: it cannot sign in or restore
// itself, OnSoftDelete runs, its recovery window runs from the imported
// DeletedAt, and past the window it is purged after OnHardDelete with its
// username kept. Without River such rows are refused whole.
func TestSecurityImportedDeletionLifecycle(t *testing.T) {
	var mu sync.Mutex
	stages := map[string][]string{}
	hook := func(stage string) func(context.Context, iam.UserDeletion) error {
		return func(_ context.Context, d iam.UserDeletion) error {
			mu.Lock()
			defer mu.Unlock()
			stages[d.UserID] = append(stages[d.UserID], stage)
			return nil
		}
	}
	stagesOf := func(id string) []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(stages[id])
	}
	h := newHost(t, withHTTP(generousLimits), authtest.WithDeps(func(d *authkit.Deps) {
		d.OnSoftDelete, d.OnHardDelete, d.OnRestore = hook("soft"), hook("hard"), hook("restore")
	}))
	ctx := context.Background()
	op := iam.SystemActor()
	raw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	recentAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	oldAt := time.Now().Add(-iam.UserRecoveryPeriod - time.Hour).UTC().Truncate(time.Microsecond)
	future := time.Now().Add(time.Hour)
	deletedRow := func(prefix string, at *time.Time) iam.ImportUser {
		name := unique(prefix)
		return iam.ImportUser{Email: name + "@security.test", EmailVerified: true, Username: name, PasswordHash: &iam.PasswordHash{Hash: string(raw), Algo: iam.HashBcrypt}, DeletedAt: at}
	}
	recent, old := deletedRow("imprecent", &recentAt), deletedRow("impold", &oldAt)
	res, err := h.auth.ImportUsers(ctx, []iam.ImportUser{recent, old, deletedRow("impfuture", &future)}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, res.Inserted)
	require.Equal(t, iam.ImportRow{Index: 2, Status: iam.ImportRejected, Reason: "invalid_deleted_at"}, res.Rows[2])
	recentID, oldID := res.Rows[0].UserID, res.Rows[1].UserID

	u, err := h.auth.User(ctx, iam.UserByID(recentID), authkit.IncludeDeleted())
	require.NoError(t, err)
	require.True(t, recentAt.Equal(*u.DeletedAt), "deleted_at %v, imported %v", u.DeletedAt, recentAt)
	_, err = h.auth.User(ctx, iam.UserByEmail(recent.Email))
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	var purgeAt time.Time
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT purge_at FROM account_deletions WHERE user_id=$1::uuid AND state='deleted'`, recentID).Scan(&purgeAt))
	require.True(t, recentAt.Add(iam.UserRecoveryPeriod).Equal(purgeAt), "the recovery window does not run from the imported deletion")
	login := h.post("/password/login", map[string]string{"identifier": recent.Email, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, login.status, login.String())
	require.Equal(t, "account_disabled", login.errorCode())

	require.NoError(t, h.auth.Start(t.Context()))
	require.Eventually(t, func() bool {
		return slices.Equal(stagesOf(recentID), []string{"soft"}) && slices.Equal(stagesOf(oldID), []string{"soft", "hard"}) && !h.userExists(oldID)
	}, 30*time.Second, 50*time.Millisecond, "recent %v, old %v", stagesOf(recentID), stagesOf(oldID))
	require.ErrorIs(t, h.auth.CheckUsername(ctx, old.Username), iam.ErrUsernameInUse, "a purged import released its username")

	require.NoError(t, opErr(h.auth.RestoreUsers(ctx, op, []string{recentID})))
	require.Eventually(t, func() bool { return slices.Equal(stagesOf(recentID), []string{"soft", "restore"}) }, 30*time.Second, 50*time.Millisecond)
	h.login(account{id: recentID, email: recent.Email})

	t.Run("without River", func(t *testing.T) {
		bare := newHost(t, withHTTP(generousLimits), authtest.WithDeps(func(d *authkit.Deps) { d.River = authkit.RiverFromHost() }))
		row := deletedRow("impnoriver", &recentAt)
		_, err := bare.auth.ImportUsers(ctx, []iam.ImportUser{row, deletedRow("impnoriverlive", nil)}, iam.ImportOptions{})
		require.Error(t, err)
		require.False(t, bare.emailTaken(row.Email))
	})
}

// providerOwner is the account holding subject, or "".
func (h *host) providerOwner(subject string) string {
	h.t.Helper()
	var id string
	require.NoError(h.t, h.pool.QueryRow(context.Background(), `SELECT COALESCE((SELECT user_id::text FROM user_providers WHERE subject=$1),'')`, subject).Scan(&id))
	return id
}

func (h *host) meID(token string) string {
	h.t.Helper()
	resp := h.get("/me", token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var me struct {
		ID string `json:"id"`
	}
	resp.json(h.t, &me)
	return me.ID
}

func (h *host) userExists(id string) bool {
	var exists bool
	err := h.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid)`, id).Scan(&exists)
	return err != nil || exists
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
