package embedded

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Deps are the runtime dependencies a Runtime is built with. Config carries
// data and policy; everything that reaches outside the process is here.
type Deps struct {
	// River is nil for managed maintenance, or RiverFromHost for a shared fleet.
	River *RiverOwnership

	// Postgres is the durable store. Required by every host-facing constructor.
	Postgres *pgxpool.Pool
	// Redis backs the ephemeral store, namespaced by Ephemeral.KeyPrefix
	// (#307). Nil selects the per-process memory store, which construction
	// refuses unless Config.Ephemeral.AllowMemory is set (#305).
	// Redis-compatible servers must provide atomic Lua execution (EVAL/EVALSHA)
	// for conditional proof claims and counters, as well as atomic GETDEL.
	Redis *redis.Client
	// EphemeralStore is a host-supplied store; mutually exclusive with Redis.
	EphemeralStore EphemeralStore
	Email          EmailSender
	SMS            SMSSender
	Entitlements   EntitlementsProvider
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
	// Clock replaces the engine clock for TTL and grace-window decisions.
	Clock func() time.Time
}

func (d Deps) validate() error {
	if d.Redis != nil && d.EphemeralStore != nil {
		return errors.New("authkit: Deps.Redis and Deps.EphemeralStore are mutually exclusive")
	}
	return nil
}

func (s *Runtime) applyDeps(d Deps) error {
	if d.Postgres != nil {
		pool, err := schemaPool(d.Postgres, s.dbSchema())
		if err != nil {
			return err
		}
		s.pg = pool
		s.q = db.New(pool)
	}
	s.redisClient = d.Redis
	s.ephemeralStore = d.EphemeralStore
	s.email = d.Email
	s.sms = d.SMS
	s.entitlements = d.Entitlements
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
func schemaPool(source *pgxpool.Pool, schema string) (*pgxpool.Pool, error) {
	if source == nil {
		return nil, nil
	}
	cfg := source.Config().Copy()
	if cfg == nil || cfg.ConnConfig == nil {
		return nil, fmt.Errorf("authkit: Postgres pool has no connection configuration")
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
