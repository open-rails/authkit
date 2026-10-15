package harness

import (
	"testing"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
)

func TestHarnessRetainsExplicitAccountDirectory(t *testing.T) {
	database := testdb.ScratchPostgres(t)
	runtime, err := New("http://localhost:9999", database.Pool)
	if err != nil {
		t.Fatal(err)
	}
	user, err := runtime.CreateUser(t.Context(), iam.NewUser{Email: "harness@example.test", Username: "harnessuser", Password: authtest.Password, EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if user.TenantID != testdb.DefaultTenantID {
		t.Fatal("wrong fixture tenant")
	}
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted, err := New("http://localhost:9999", database.Pool)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(t.Context())
	found, err := restarted.User(t.Context(), iam.UserByEmail("harness@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != found.ID {
		t.Fatal("fixture directory changed across restart")
	}
}
