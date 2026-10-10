package engine

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/internal/db"
)

// The users triggers (migration 0010) are the outbox's only writers, so no
// code path can change a pushed account without recording it. This keeps
// them complete: every users column a SCIM User or a contact reads is one the
// triggers watch, so a new column a resource starts showing fails here until
// the triggers watch it too.
func TestProvisioningTriggersWatchWhatIsPushed(t *testing.T) {
	sql, err := os.ReadFile("../migrations/postgres/0010_provisioning.up.sql")
	require.NoError(t, err)
	watched := func(when string) []string {
		m := regexp.MustCompile(`(?s)` + when + ` UPDATE OF ([a-z_, ]+) ON users\s+FOR EACH ROW\s+WHEN \(ROW\(([^)]*)\)`).FindSubmatch(sql)
		require.NotNil(t, m, "no %s UPDATE OF trigger on users", when)
		columns := strings.Split(string(m[1]), ", ")
		var rowed []string
		for _, c := range strings.Split(string(m[2]), ", ") {
			rowed = append(rowed, strings.TrimPrefix(c, "OLD."))
		}
		require.Equal(t, columns, rowed, "%s trigger: its WHEN compares the columns it watches", when)
		return columns
	}
	outbox, profile := watched("AFTER"), watched("BEFORE")
	require.Equal(t, outbox, profile, "profile_updated_at moves exactly when a change is recorded")

	asOf := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	email, name := "alice@example.com", "alice"
	base := db.User{ID: "0192f6a0-0000-7000-8000-000000000001", Email: &email, Username: &name, EmailVerified: true, CreatedAt: asOf.Add(-time.Hour)}
	shown := func(u db.User) string { return resourceDigest(scimUser(u, asOf)) }
	var read []string
	typ := reflect.TypeFor[db.User]()
	for i := range typ.NumField() {
		f := typ.Field(i)
		// ID is immutable (enforce_canonical_name_claim); the trigger itself
		// moves profile_updated_at when a column it watches changes.
		if f.Name == "ID" || f.Name == "ProfileUpdatedAt" {
			continue
		}
		changed := base
		v := reflect.ValueOf(&changed).Elem().Field(i)
		switch v.Interface().(type) {
		case string:
			v.SetString(v.String() + "x")
		case bool:
			v.SetBool(!v.Bool())
		case int64:
			v.SetInt(v.Int() + 1)
		case []byte:
			v.SetBytes([]byte(`{"x":1}`))
		case time.Time:
			v.Set(reflect.ValueOf(asOf.Add(-time.Minute)))
		case *string:
			other := "other"
			v.Set(reflect.ValueOf(&other))
		case *time.Time:
			earlier := asOf.Add(-time.Minute)
			v.Set(reflect.ValueOf(&earlier))
		default:
			t.Fatalf("db.User.%s: teach this test to vary a %s", f.Name, f.Type)
		}
		if shown(changed) != shown(base) || accountUserInfo(changed) != accountUserInfo(base) {
			read = append(read, snake(f.Name))
		}
	}
	require.NotEmpty(t, read)
	for _, column := range read {
		require.True(t, slices.Contains(outbox, column), "a SCIM User shows users.%s, which the provisioning triggers do not watch (%v)", column, outbox)
	}
}

func snake(name string) string {
	var b strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
