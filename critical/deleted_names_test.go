package critical_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testclock"
)

// #472, #488: a purged account's name stays reserved forever (the naming
// policy). The recovery window holds the name, and the account's former
// names keep their own expiry.
func TestCriticalDeletedNames(t *testing.T) {
	t.Parallel()
	// purge deletes u for good through the real purge worker.
	purge := func(t *testing.T, f *fixture, u authtest.User) {
		t.Helper()
		rows, err := f.auth.PurgeUsers(t.Context(), []string{u.ID})
		goodBatch(t, rows, err)
		f.purged(t, u.ID)
	}
	taken := func(t *testing.T, f *fixture, name string) {
		t.Helper()
		if err := f.auth.CheckUsername(t.Context(), name); !errors.Is(err, iam.ErrUsernameInUse) {
			t.Fatalf("CheckUsername(%q) = %v, want ErrUsernameInUse", name, err)
		}
		if _, err := f.auth.CreateUser(t.Context(), iam.NewUser{Username: name}); !errors.Is(err, iam.ErrUsernameInUse) {
			t.Fatalf("a new account took reserved %q: %v", name, err)
		}
		if got, err := f.auth.ResolveUsername(t.Context(), name); !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("reserved %q resolved to %+v, %v", name, got, err)
		}
	}
	reservation := func(t *testing.T, f *fixture, name string) *time.Time {
		t.Helper()
		var expires *time.Time
		noError(t, f.pool.QueryRow(t.Context(), "SELECT expires_at FROM "+pgx.Identifier{f.schema, "name_claims"}.Sanitize()+" WHERE name=$1 AND NOT canonical", name).Scan(&expires))
		return expires
	}
	policy := func(t *testing.T, f *fixture, mode string, seconds int64) {
		t.Helper()
		var caps struct {
			Username struct {
				Policy struct {
					Mode    string `json:"deleted_name_retention_mode"`
					Seconds int64  `json:"deleted_name_retention_seconds"`
				} `json:"former_names"`
			} `json:"username"`
		}
		r := f.call(t, "GET", "/capabilities", "", nil)
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &caps)
		if got := caps.Username.Policy; got.Mode != mode || got.Seconds != seconds {
			t.Fatalf("capabilities report deleted names %s/%ds, want %s/%ds", got.Mode, got.Seconds, mode, seconds)
		}
	}

	t.Run("AK-J38-C01_by_default_a_purged_name_is_reserved_forever", func(t *testing.T) {
		f := newFixture(t)
		clock := testclock.Wall()
		testclock.Use(f.auth, clock.Now)
		f.startFleet(t)
		policy(t, f, "forever", 0)
		u, live := f.user(t), f.user(t)
		purge(t, f, u)
		if expires := reservation(t, f, u.Username); expires != nil {
			t.Fatalf("default reservation expires at %v, want never", expires)
		}
		clock.Advance(100 * 365 * 24 * time.Hour)
		taken(t, f, u.Username)
		// The reserved name answers exactly as a live account's name does.
		reserved := f.call(t, "GET", "/usernames/availability?username="+u.Username, "", nil)
		held := f.call(t, "GET", "/usernames/availability?username="+live.Username, "", nil)
		if reserved.status != http.StatusOK || string(reserved.body) != string(held.body) {
			t.Fatalf("reserved name answered %d %s, a live name %d %s", reserved.status, reserved.body, held.status, held.body)
		}
	})

	t.Run("AK-J38-C03_a_purged_name_is_kept_and_its_former_names_keep_their_expiry", func(t *testing.T) {
		f := newFixture(t)
		f.startFleet(t)
		policy(t, f, "forever", 0)
		u := f.user(t)
		former, current := u.Username, "renamed"+u.Username[4:]
		_, err := f.auth.UpdateUser(t.Context(), f.identity(t, f.signIn(t, u).AccessToken), u.ID, iam.UserUpdate{Username: &current})
		noError(t, err)
		promised := reservation(t, f, former)
		purge(t, f, u)
		taken(t, f, current)
		// The former name keeps the 90 days its rename promised.
		taken(t, f, former)
		if kept := reservation(t, f, former); promised == nil || kept == nil || !kept.Equal(*promised) {
			t.Fatalf("purge changed the former name's expiry from %v to %v", promised, kept)
		}
	})

	t.Run("AK-J38-C04_the_recovery_window_holds_the_name_and_the_purge_keeps_it", func(t *testing.T) {
		f := newFixture(t)
		fleet := f.startFleet(t)
		u := f.user(t)
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		if err := f.auth.CheckUsername(t.Context(), u.Username); !errors.Is(err, iam.ErrUsernameInUse) {
			t.Fatalf("a deleted account's name was free inside its recovery window: %v", err)
		}
		if _, err := f.auth.CreateUser(t.Context(), iam.NewUser{Username: u.Username}); !errors.Is(err, iam.ErrUsernameInUse) {
			t.Fatalf("a new account took a deleted account's name inside its window: %v", err)
		}
		// The real due sweep inside the window purges nothing and frees nothing.
		f.retrySweep(t, fleet, "authkit_account_delete_due", authtest.Issuer)
		if err := f.auth.CheckUsername(t.Context(), u.Username); !errors.Is(err, iam.ErrUsernameInUse) {
			t.Fatalf("a sweep inside the window freed the name: %v", err)
		}
		rows, err = f.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		back, err := f.auth.ResolveUsername(t.Context(), u.Username)
		noError(t, err)
		if back.ID != u.ID || back.IsAlias {
			t.Fatalf("restored account's name resolved to %+v", back)
		}
		rows, err = f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		purge(t, f, u)
		taken(t, f, u.Username)
	})
}
