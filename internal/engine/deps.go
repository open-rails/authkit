package engine

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/dpop"
)

func (s *Engine) applyDeps(d config.Deps) error {
	if d.Postgres != nil {
		pool, err := schemaPool(d.Postgres, s.dbSchema())
		if err != nil {
			return err
		}
		s.pg = pool
		s.q = db.New(pool)
		// Flows read and claim ephemeral state while holding a transaction's
		// connection. A separate small pool keeps those single statements from
		// waiting on connections held by the transactions waiting on them.
		ephemeralPool, err := schemaPool(d.Postgres, s.dbSchema(), func(c *pgxpool.Config) {
			c.MaxConns = max(2, c.MaxConns/4)
			c.MinConns = 0
			c.MaxConnIdleTime = time.Minute
		})
		if err != nil {
			pool.Close()
			return err
		}
		s.ephemeral = &ephemeralKV{pool: ephemeralPool, q: db.New(ephemeralPool)}
	}
	s.redis = d.Redis
	s.replays = dpop.NewReplays(d.Redis)
	s.resourceHosts = d.ResourceHosts
	s.providers = slices.Clone(d.Providers)
	s.email, s.sms = d.Email, d.SMS
	s.entitlements, s.entitlementHolders = d.Entitlements, d.EntitlementHolders
	s.onEvent, s.onPurge = d.OnEvent, d.OnPurge
	s.oauthGrants = d.OAuthGrants
	s.nameAdmission = d.NameAdmission
	s.deletionCheck = d.DeletionCheck
	return nil
}

// schemaPool creates an AuthKit-owned pool whose every connection resolves
// unqualified AuthKit SQL against schema, followed by public. The caller's
// pool is never modified: hosts commonly share it with unrelated queries,
// and changing its search_path would leak AuthKit's namespace into those
// queries. The clone preserves the host pool's connection hooks, then applies
// the AuthKit search_path after the host's AfterConnect hook has run.
func schemaPool(source *pgxpool.Pool, schema string, tune ...func(*pgxpool.Config)) (*pgxpool.Pool, error) {
	if source == nil {
		return nil, nil
	}
	cfg := source.Config().Copy()
	if cfg == nil || cfg.ConnConfig == nil {
		return nil, fmt.Errorf("authkit: Postgres pool has no connection configuration")
	}
	for _, t := range tune {
		t(cfg)
	}
	searchPath := pgx.Identifier{schema}.Sanitize() + ", public"
	setSearchPath := func(cc *pgx.ConnConfig) {
		if cc.RuntimeParams == nil {
			cc.RuntimeParams = make(map[string]string)
		}
		cc.RuntimeParams["search_path"] = searchPath
	}
	setSearchPath(cfg.ConnConfig)
	beforeConnect := cfg.BeforeConnect
	cfg.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
		if beforeConnect != nil {
			if err := beforeConnect(ctx, cc); err != nil {
				return err
			}
		}
		setSearchPath(cc)
		return nil
	}
	afterConnect := cfg.AfterConnect
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if afterConnect != nil {
			if err := afterConnect(ctx, conn); err != nil {
				return err
			}
		}
		return db.New(conn).SetSearchPath(ctx, db.SetSearchPathParams{SearchPath: searchPath})
	}
	return pgxpool.NewWithConfig(context.Background(), cfg)
}
