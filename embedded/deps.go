package embedded

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Deps are the runtime dependencies a Runtime is built with. Config carries
// data and policy; everything that reaches outside the process is here.
type Deps struct {
	// River is nil for managed maintenance, or RiverFromHost for a shared fleet.
	River *RiverOwnership

	// Postgres is the durable store. Required by every host-facing constructor.
	// It also holds AuthKit's short-lived auth state (codes, ceremonies,
	// attempt counters), shared by every replica.
	Postgres     *pgxpool.Pool
	Email        EmailSender
	SMS          SMSSender
	Entitlements EntitlementsProvider
	// Deletion hooks run durably through River, never inside the request's
	// transaction. Soft deletion must preserve recoverable host data; hard
	// deletion is finalization work after 30 days and before identity purge.
	// Hooks must be idempotent and honor context cancellation. Nil means no
	// application work for that stage. OnRestore undoes reversible soft work.
	OnSoftDelete func(context.Context, authkit.UserDeletion) error
	OnHardDelete func(context.Context, authkit.UserDeletion) error
	OnRestore    func(context.Context, authkit.UserDeletion) error
	// DelegatedAuthorization is the host's delegation authorizer for the
	// delegated-token mint route (#261/#277); its grant is the complete
	// authority AuthKit signs. Required when Delegated.Audiences is set.
	DelegatedAuthorization DelegationAuthorizer
	// ApplicationAdmission is consulted before any application
	// self-registration fetch (#264): a non-nil error refuses the attempt.
	ApplicationAdmission func(ctx context.Context, domain string) error
	// InstanceAdmission is consulted before any generated persona-instance
	// creation (#263) with the normalized slug; a non-nil error refuses.
	InstanceAdmission func(ctx context.Context, group authkit.GroupRef, subject string) error
	// NameAdmission is the host's side-effect-free namespace policy for
	// creation and rename.
	NameAdmission func(context.Context, authkit.NameAdmissionRequest) error
	// SolanaSNSResolver replaces the SNS primary-name resolver used after a
	// verified Solana link.
	SolanaSNSResolver SolanaSNSResolver
	// OutboundHTTP overrides the client for application-document and JWKS
	// fetches (#264); nil builds the timeout-bounded, redirect-refusing,
	// SSRF-guarded default.
	OutboundHTTP *http.Client
	// Clock replaces the engine clock for TTL and grace-window decisions. It
	// never governs ephemeral state (codes, claims, counters), which always
	// expires by the database clock so replicas agree.
	Clock func() time.Time
}

func (s *engine) applyDeps(d Deps) error {
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
	s.entitlements = d.Entitlements
	s.onSoftDelete, s.onHardDelete, s.onRestore = d.OnSoftDelete, d.OnHardDelete, d.OnRestore
	s.delegationAuthorizer = d.DelegatedAuthorization
	s.appAdmission = d.ApplicationAdmission
	s.instanceAdmission = d.InstanceAdmission
	s.nameAdmission = d.NameAdmission
	if d.SolanaSNSResolver != nil {
		s.solanaSNSResolver = d.SolanaSNSResolver
	}
	s.appHTTPClient = d.OutboundHTTP
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
