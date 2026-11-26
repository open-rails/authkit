// Package pgsession dials the PostgreSQL sessions a transaction pooler cannot
// carry (LISTEN, session advisory locks) and checks that a pool may go through
// one.
package pgsession

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Dial opens one connection of cfg, running its BeforeConnect and
// AfterConnect hooks as the pool would.
func Dial(ctx context.Context, cfg *pgxpool.Config) (*pgx.Conn, error) {
	if cfg == nil || cfg.ConnConfig == nil {
		return nil, errors.New("authkit: session configuration has no connection settings")
	}
	cc := cfg.ConnConfig.Copy()
	if cfg.BeforeConnect != nil {
		if err := cfg.BeforeConnect(ctx, cc); err != nil {
			return nil, err
		}
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, err
	}
	if cfg.AfterConnect != nil {
		if err := cfg.AfterConnect(ctx, conn); err != nil {
			_ = conn.Close(context.WithoutCancel(ctx))
			return nil, err
		}
	}
	return conn, nil
}

// CheckPooled refuses a pool whose statements a transaction pooler would
// break: one that prepares in one round trip and executes in another, or keeps
// named statements on a server connection.
func CheckPooled(pool *pgxpool.Pool) error {
	switch mode := pool.Config().ConnConfig.DefaultQueryExecMode; mode {
	case pgx.QueryExecModeCacheDescribe, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol:
		return nil
	default:
		return fmt.Errorf("authkit: Deps.Postgres goes through a transaction pooler (Deps.PostgresSession is set) and needs DefaultQueryExecMode cache_describe, exec or simple_protocol, not %s", mode)
	}
}

// CheckSearchPath proves pool's pooler keeps each client's startup
// search_path, as AuthKit's tables resolve through it: a client that names
// probe, a list no other client uses, must run its transactions with it.
func CheckSearchPath(ctx context.Context, pool *pgxpool.Pool, probe string) error {
	cfg := pool.Config()
	cc := cfg.ConnConfig.Copy()
	if cfg.BeforeConnect != nil {
		if err := cfg.BeforeConnect(ctx, cc); err != nil {
			return err
		}
	}
	if cc.RuntimeParams == nil {
		cc.RuntimeParams = map[string]string{}
	}
	cc.RuntimeParams["search_path"] = probe
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		if strings.Contains(err.Error(), "search_path") {
			return fmt.Errorf("%w: %w", errUntracked, err)
		}
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var got string
	if err := conn.QueryRow(ctx, "SELECT current_setting('search_path')").Scan(&got); err != nil {
		return err
	}
	if got != probe {
		return fmt.Errorf("%w: a client that connected with %s ran with %s", errUntracked, probe, got)
	}
	return nil
}

var errUntracked = errors.New("authkit: the transaction pooler does not keep each client's search_path; PgBouncer 1.26 tracks it, an earlier one with track_extra_parameters = search_path, and neither may list it in ignore_startup_parameters")
