package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

// Deps mirrors authkit.Deps; the root package maps it (config_map.go).
type Deps struct {
	River                  *RiverOwnership
	Postgres               *pgxpool.Pool
	Email                  EmailSender
	SMS                    SMSSender
	Entitlements           EntitlementsProvider
	OnSoftDelete           func(context.Context, iam.UserDeletion) error
	OnHardDelete           func(context.Context, iam.UserDeletion) error
	OnRestore              func(context.Context, iam.UserDeletion) error
	OnEvent                func(context.Context, iam.Event) error
	DelegatedAuthorization iam.DelegationAuthorizer
	NameAdmission          func(context.Context, iam.NameAdmissionRequest) error
	Clock                  func() time.Time
	// SolanaSNSResolver replaces the SNS resolver in AuthKit's own tests.
	SolanaSNSResolver SolanaSNSResolver
}

func (s *Engine) applyDeps(d Deps) error {
	if d.OnEvent != nil && d.Postgres == nil {
		return errors.New("authkit: OnEvent requires Deps.Postgres")
	}
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
	s.email = d.Email
	s.sms = d.SMS
	s.SetEntitlements(d.Entitlements)
	s.onSoftDelete, s.onHardDelete, s.onRestore = d.OnSoftDelete, d.OnHardDelete, d.OnRestore
	s.onEvent = d.OnEvent
	s.delegationAuthorizer = d.DelegatedAuthorization
	s.nameAdmission = d.NameAdmission
	if d.SolanaSNSResolver != nil {
		s.solanaSNSResolver = d.SolanaSNSResolver
	}
	if d.Clock != nil {
		s.now = d.Clock
	}
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
		_, err := conn.Exec(ctx, "SET search_path TO "+searchPath)
		return err
	}
	return pgxpool.NewWithConfig(context.Background(), cfg)
}
