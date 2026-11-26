package critical_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// setupLog records what Start says about the first administrator: each
// setup link it logs, and each reminder of a live one.
type setupLog struct {
	mu        sync.Mutex
	urls      []string
	reminders int
}

func (l *setupLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *setupLog) Handle(_ context.Context, r slog.Record) error {
	if !strings.Contains(r.Message, "no administrator yet") {
		return nil
	}
	var link string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "url" {
			link = a.Value.String()
		}
		return true
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	if link == "" {
		l.reminders++
	} else {
		l.urls = append(l.urls, link)
	}
	return nil
}
func (l *setupLog) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *setupLog) WithGroup(string) slog.Handler      { return l }

// said is how many links and reminders Start has logged.
func (l *setupLog) said() (links []string, reminders int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.urls), l.reminders
}

// setupFixture is a fixture whose Logger is logs.
func setupFixture(t *testing.T, logs *setupLog, options ...authtest.Option) *fixture {
	t.Helper()
	return newFixture(t, append([]authtest.Option{authtest.WithDeps(func(d *authkit.Deps) { d.Logger = slog.New(logs) })}, options...)...)
}

// setupToken is the token of a setup link, which opens the frontend's
// /setup page with the token in its fragment.
func setupToken(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	noError(t, err)
	q, err := url.ParseQuery(u.Fragment)
	noError(t, err)
	if !strings.HasSuffix(u.Path, "/setup") || q.Get("token") == "" || u.RawQuery != "" {
		t.Fatalf("setup link %q does not carry its token in the /setup page's fragment", link)
	}
	return q.Get("token")
}

func (f *fixture) setup(t *testing.T, token, email, username string) response {
	t.Helper()
	return f.call(t, "POST", "/setup", "", map[string]string{"token": token, "email": email, "username": username, "password": authtest.Password})
}

// rootRole is the role account id holds on root, if any.
func (f *fixture) rootRole(t *testing.T, id string) iam.Role {
	t.Helper()
	roles, err := f.auth.GroupRoles(t.Context(), iam.RootGroup(), []iam.Subject{iam.UserSubject(id)})
	noError(t, err)
	return roles[iam.UserSubject(id)]
}

// noAccount fails unless no account holds email.
func (f *fixture) noAccount(t *testing.T, email string) {
	t.Helper()
	if _, err := f.auth.User(t.Context(), iam.UserByEmail(email)); !errors.Is(err, iam.ErrUserNotFound) {
		t.Errorf("an account holds %s: %v", email, err)
	}
}

// expireSetupLink moves the live setup link's expiry into the past. Expiry
// is PostgreSQL's clock; outcomes are observed through public requests.
func (f *fixture) expireSetupLink(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "ephemeral_kv"}.Sanitize()+" SET expires_at = statement_timestamp() - interval '1 second' WHERE key = 'setup:link'")
	noError(t, err)
}

func TestCriticalFirstAdministrator(t *testing.T) {
	t.Parallel()
	t.Run("AK-J48-C01_a_fresh_deployment_logs_one_setup_link_that_creates_the_owner_once", func(t *testing.T) {
		logs := &setupLog{}
		f := setupFixture(t, logs, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor = iam.TwoFactorOptional }))
		noError(t, f.auth.Start(t.Context()))
		links, _ := logs.said()
		if len(links) != 1 {
			t.Fatalf("a fresh deployment logged %d setup links, want 1", len(links))
		}
		token := setupToken(t, links[0])

		// A restart while the link lives logs no other one, only a reminder.
		noError(t, authtest.Replica(t, f.auth).Start(t.Context()))
		if again, reminders := logs.said(); len(again) != 1 || reminders != 1 {
			t.Fatalf("a restart logged %d links and %d reminders, want the first link alone and one reminder", len(again), reminders)
		}

		// The link creates the owner, whose first sign-in enrolls a second
		// factor before any session exists.
		const email = "first-owner@example.com"
		enroll := enrollmentToken(t, f.setup(t, token, email, "firstowner"))
		owner, err := f.auth.User(t.Context(), iam.UserByEmail(email))
		noError(t, err)
		if owner.EmailVerified {
			t.Error("setup proved an address nobody proved")
		}
		if role := f.rootRole(t, owner.ID); role != iam.RootPersona().OwnerRole() {
			t.Fatalf("the setup account holds %q on root, want the owner role", role)
		}
		_, created := f.totp(t, enroll)
		session := factorSession(t, created, owner.ID)
		f.call(t, "GET", "/groups/root/members", session.AccessToken, nil).want(t, http.StatusOK, "")

		// Spent: it creates nobody else, however often it is opened.
		f.setup(t, token, "second-owner@example.com", "secondowner").want(t, http.StatusNotFound, "setup_link_invalid")
		f.noAccount(t, "second-owner@example.com")

		// With an owner, a start logs nothing about setup.
		noError(t, authtest.Replica(t, f.auth).Start(t.Context()))
		if again, reminders := logs.said(); len(again) != 1 || reminders != 1 {
			t.Fatalf("a start with an owner logged %d links and %d reminders", len(again), reminders)
		}
	})
	t.Run("AK-J48-C02_a_startup_link_dies_with_an_administrator_and_expiry_and_only_the_hosts_link_outlives_them", func(t *testing.T) {
		logs := &setupLog{}
		f := setupFixture(t, logs)
		noError(t, f.auth.Start(t.Context()))
		links, _ := logs.said()
		if len(links) != 1 {
			t.Fatalf("a fresh deployment logged %d setup links, want 1", len(links))
		}
		expired := setupToken(t, links[0])

		// After its expiry the next start logs a new link; the old one is dead.
		f.expireSetupLink(t)
		noError(t, authtest.Replica(t, f.auth).Start(t.Context()))
		links, _ = logs.said()
		if len(links) != 2 {
			t.Fatalf("a start after expiry logged %d links in all, want 2", len(links))
		}
		live := setupToken(t, links[1])
		if live == expired {
			t.Fatal("the replacement link reuses the expired token")
		}
		f.setup(t, expired, "expired-link@example.com", "expiredlink").want(t, http.StatusNotFound, "setup_link_invalid")
		f.noAccount(t, "expired-link@example.com")

		// Once anyone holds a root role, Start's link creates nobody.
		staff := f.user(t)
		_, err := f.auth.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(staff.ID), f.rootReader)
		noError(t, err)
		f.setup(t, live, "late-owner@example.com", "lateowner").want(t, http.StatusNotFound, "setup_link_invalid")
		f.noAccount(t, "late-owner@example.com")

		// The host's break-glass link works while administrators exist, once,
		// under concurrent use.
		issued, err := f.auth.IssueSetupLink(t.Context())
		noError(t, err)
		if !issued.ExpiresAt.After(time.Now().Add(23 * time.Hour)) {
			t.Fatalf("the host's link expires at %v, want a day", issued.ExpiresAt)
		}
		token := setupToken(t, issued.URL)
		statuses := make(chan int, 2)
		var wg sync.WaitGroup
		for i, name := range []string{"breakglassa", "breakglassb"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := f.request(t.Context(), "POST", "/setup", "", map[string]string{"token": token, "email": name + "@example.com", "username": name, "password": authtest.Password})
				if err != nil {
					t.Errorf("setup %d: %v", i, err)
					return
				}
				statuses <- r.status
			}()
		}
		wg.Wait()
		close(statuses)
		var won []int
		for status := range statuses {
			won = append(won, status)
		}
		slices.Sort(won)
		if !slices.Equal(won, []int{http.StatusOK, http.StatusNotFound}) {
			t.Fatalf("two uses of one link answered %v, want one owner and one refusal", won)
		}
		owners := 0
		for _, name := range []string{"breakglassa", "breakglassb"} {
			u, err := f.auth.User(t.Context(), iam.UserByEmail(name+"@example.com"))
			if errors.Is(err, iam.ErrUserNotFound) {
				continue
			}
			noError(t, err)
			if f.rootRole(t, u.ID) == iam.RootPersona().OwnerRole() {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("the host's link made %d owners, want 1", owners)
		}
		if again, _ := logs.said(); len(again) != 2 {
			t.Fatalf("issuing a link logged it: %d links", len(again))
		}
	})
	t.Run("AK-J48-C03_without_the_setup_routes_no_link_is_logged_or_issued", func(t *testing.T) {
		logs := &setupLog{}
		f := setupFixture(t, logs, authtest.WithConfig(func(c *authkit.Config) { unmountGroup(c, iam.RouteSetup) }))
		noError(t, f.auth.Start(t.Context()))
		if links, reminders := logs.said(); len(links)+reminders != 0 {
			t.Fatalf("Start logged %d setup links and %d reminders with setup unmounted", len(links), reminders)
		}
		if _, err := f.auth.IssueSetupLink(t.Context()); err == nil {
			t.Fatal("IssueSetupLink issued a link nobody can open")
		}
		f.call(t, "POST", "/setup", "", map[string]string{"token": "x"}).want(t, http.StatusNotFound, "")
		var caps struct {
			RouteGroups []iam.RouteGroup `json:"route_groups"`
		}
		r := f.call(t, "GET", "/capabilities", "", nil)
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &caps)
		if slices.Contains(caps.RouteGroups, iam.RouteSetup) || !slices.Contains(caps.RouteGroups, iam.RoutePermissionGroups) || !slices.Contains(caps.RouteGroups, iam.RouteInvitations) {
			t.Fatalf("capabilities report route groups %v", caps.RouteGroups)
		}
	})
}
