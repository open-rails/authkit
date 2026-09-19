package embedded

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSchemaPoolIsolatesSearchPathFromHostPool(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://authkit:test@127.0.0.1:1/authkit")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MinConns = 0
	cfg.MaxConns = 1
	host, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	bound, err := schemaPool(host, "tenant_auth")
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()

	if got := host.Config().ConnConfig.RuntimeParams["search_path"]; got != "" {
		t.Fatalf("host pool search_path changed to %q", got)
	}
	if got, want := bound.Config().ConnConfig.RuntimeParams["search_path"], `"tenant_auth", public`; got != want {
		t.Fatalf("bound search_path = %q, want %q", got, want)
	}
}
