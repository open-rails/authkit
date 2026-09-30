package apitest_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
)

// The admin user directory finds an account the ways support looks one up,
// each through an index, and pages by keyset, counting every match when asked.
func TestAdminUserDirectory(t *testing.T) {
	ctx := t.Context()
	traced := &directorySQL{}
	cfg, err := pgxpool.ParseConfig(testdb.URL(t))
	require.NoError(t, err)
	cfg.ConnConfig.Tracer = traced
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	idp := testidp.New(t)
	rbac := authkit.NewRoles()
	staffRole := rbac.Root.Role("staff", rbac.Root.Users.Read)
	auth, _ := authtest.New(t, withProviders(idp.OIDC("idp")), authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = pool }),
		authtest.WithConfig(func(c *authkit.Config) {
			c.Roles = rbac
			c.TwoFactor.Mode = iam.TwoFactorDisabled
		}))
	a := newAPI(t, auth)
	staff := authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), staffRole)
	token := authtest.SignIn(t, auth, staff).AccessToken

	create := func(u iam.NewUser) string {
		t.Helper()
		got, err := auth.CreateUser(ctx, u)
		require.NoError(t, err)
		return got.ID
	}
	alice := create(iam.NewUser{Username: "alice_z7", Email: "alice.z7@example.test", Phone: "+15555550123"})
	lookalike := create(iam.NewUser{Username: "aliceXz7", Email: "alicexz7@example.test"})
	bob := create(iam.NewUser{Username: "bobby", Email: "bob@example.test"})
	require.NoError(t, auth.LinkProvider(ctx, bob, iam.ProviderLink{Issuer: "https://accounts.example.test", Provider: "google", Subject: "g-1029384756", Email: "Bob.Personal@Gmail.test"}))
	carol := create(iam.NewUser{Username: "carol", Email: "carol@example.test"})
	const wallet = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	imported, err := auth.ImportSolanaLinks(ctx, []iam.ImportSolanaLink{{UserID: carol, Address: wallet, Source: "legacy", SourceID: "1"}})
	require.NoError(t, err)
	require.Equal(t, 1, imported.Inserted)
	expectAnswer(t, providerSignIn(t, a, idp, "idp", testidp.Identity{Subject: "idp-dave-1", Email: "dave.idp@example.test", EmailVerified: true, Username: "DaveOnTheIdP"}, ""), http.StatusOK)
	dave, err := auth.User(ctx, iam.UserByEmail("dave.idp@example.test"))
	require.NoError(t, err)
	// Renamed, so only the link still carries the provider username.
	renamed := "dave_account"
	_, err = auth.UpdateUser(ctx, iam.SystemActor(), dave.ID, iam.UserUpdate{Username: &renamed})
	require.NoError(t, err)

	list := func(query string) (iam.ListPage[iam.UserEntry], string) {
		t.Helper()
		res := expect(t, http.StatusOK, a.get("/admin/users?"+query, token))
		var page iam.ListPage[iam.UserEntry]
		res.decode(t, &page)
		return page, res.String()
	}

	t.Run("search", func(t *testing.T) {
		for search, want := range map[string][]string{
			"CE.Z7@EXAMPLE":           {alice},            // within an email, in any case
			"ice_z":                   {alice},            // within a username; _ is no wildcard
			"5550123":                 {alice},            // within a phone number
			"al":                      {alice, lookalike}, // below three characters, at the start
			"ce":                      {},
			alice:                     {alice}, // the account id
			strings.ToUpper(alice):    {alice},
			"g-1029384756":            {bob}, // a linked sign-in's subject
			"bob.personal@gmail.TEST": {bob}, // its provider email, in any case
			"g-10293847":              {},    // linked identifiers match whole
			wallet:                    {carol},
			strings.ToLower(wallet):   {}, // wallet addresses are case-sensitive
			"daveontheidp":            {dave.ID},
			"idp-dave-1":              {dave.ID},
			"%":                       {}, // wildcards are literal
			"_":                       {},
			`\`:                       {},
			"a%z":                     {},
		} {
			page, _ := list("status=any&search=" + url.QueryEscape(search))
			got := []string{}
			for _, u := range page.Items {
				got = append(got, u.ID)
			}
			require.ElementsMatch(t, want, got, "search %q", search)
		}
	})

	t.Run("filters, keyset paging and total", func(t *testing.T) {
		ids := map[string]string{}
		for _, name := range []string{"pagera", "pagerb", "pagerc", "pagerd", "pagere"} {
			ids[name] = create(iam.NewUser{Username: name, Email: name + "@example.test"})
		}
		require.NoError(t, auth.Ban(ctx, iam.SystemActor(), ids["pagerc"], iam.Ban{}))
		authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(ids["pagerd"]), staffRole)
		walk := func(query string) (names []string, totals []int) {
			t.Helper()
			cursor := ""
			for range 10 {
				page, _ := list(query + cursor)
				for _, u := range page.Items {
					names = append(names, u.Username)
				}
				if page.Total != nil {
					totals = append(totals, *page.Total)
				}
				if page.Next == "" {
					return names, totals
				}
				cursor = "&cursor=" + url.QueryEscape(page.Next)
			}
			t.Fatal("paging never ended")
			return nil, nil
		}
		names, totals := walk("search=pager&sort=username&order=asc&limit=2&total=true")
		require.Equal(t, []string{"pagera", "pagerb", "pagerc", "pagerd", "pagere"}, names)
		require.Equal(t, []int{5, 5, 5}, totals, "the total counts every match, whatever the page")
		names, totals = walk("search=PAGER&status=active&sort=username&order=desc&limit=2&total=true")
		require.Equal(t, []string{"pagere", "pagerd", "pagerb", "pagera"}, names)
		require.Equal(t, []int{4, 4}, totals)
		names, _ = walk("search=pager&status=banned")
		require.Equal(t, []string{"pagerc"}, names)
		names, totals = walk("search=pager&root_role=" + staffRole.String() + "&total=true")
		require.Equal(t, []string{"pagerd"}, names)
		require.Equal(t, []int{1}, totals)

		_, raw := list("search=pager")
		require.Contains(t, raw, `"total":null`, "no count unless asked")
		res := a.get("/admin/users?total=yes", token)
		require.Equal(t, http.StatusBadRequest, res.status, res.String())
		var env struct {
			Error struct {
				Code  string `json:"code"`
				Param string `json:"param"`
			} `json:"error"`
		}
		res.decode(t, &env)
		require.Equal(t, "invalid_request", env.Error.Code)
		require.Equal(t, "total", env.Error.Param)
	})

	// Sequential and plain index scans are off, so a search branch no index
	// serves would force a disabled scan into the plan (see explain).
	t.Run("every search branch is indexed", func(t *testing.T) {
		traced.take()
		list("status=any&total=true&search=" + alice)
		list("status=any&search=al")
		queries := traced.take()
		require.Len(t, queries, 3, "the count and the page, then a page")
		for i, q := range queries {
			plan := explain(t, pool, q)
			require.NotContains(t, plan, "Seq Scan", plan)
			require.NotContains(t, plan, "Disabled", plan)
			indexes := []string{"users_username_trgm_idx", "users_email_trgm_idx", "users_phone_number_trgm_idx",
				"user_providers_subject_idx", "user_providers_email_lower_idx", "user_providers_username_lower_idx"}
			if i < 2 {
				indexes = append(indexes, "users_pkey") // the uuid
			}
			for _, index := range indexes {
				require.Contains(t, plan, "Bitmap Index Scan on "+index, plan)
			}
		}
	})
}

// directorySQL records the user directory's queries as the engine sends them.
type directorySQL struct {
	mu      sync.Mutex
	queries []directoryQuery
}

type directoryQuery struct {
	sql, searchPath string
	args            []any
}

func (d *directorySQL) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT u.id::text, ") || strings.HasPrefix(data.SQL, "SELECT count(*) FROM users u ") {
		d.mu.Lock()
		d.queries = append(d.queries, directoryQuery{sql: data.SQL, searchPath: conn.Config().RuntimeParams["search_path"], args: data.Args})
		d.mu.Unlock()
	}
	return ctx
}

func (*directorySQL) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (d *directorySQL) take() []directoryQuery {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.queries
	d.queries = nil
	return out
}

// explain plans q as the engine ran it, with sequential and plain index scans
// disabled. A partial index a branch implies can serve it by a whole-index
// scan, which a table of a dozen rows prefers to the branch's own index: with
// status=any that is only users_email_uidx (email IS NOT NULL), dropped inside
// the rolled-back transaction.
func explain(t *testing.T, pool *pgxpool.Pool, q directoryQuery) string {
	t.Helper()
	ctx := t.Context()
	require.NotEmpty(t, q.searchPath)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT set_config('search_path', $1, true), set_config('enable_seqscan', 'off', true),
		set_config('enable_indexscan', 'off', true), set_config('enable_indexonlyscan', 'off', true)`, q.searchPath)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `DROP INDEX users_email_uidx`)
	require.NoError(t, err)
	rows, err := tx.Query(ctx, "EXPLAIN "+q.sql, q.args...)
	require.NoError(t, err)
	lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return strings.Join(lines, "\n")
}
