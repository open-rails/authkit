package authcore

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Deps are the runtime dependencies a Service is built with. Config carries
// data and policy; everything that reaches outside the process is here.
type Deps struct {
	// Postgres is the durable store. Required by every host-facing constructor.
	Postgres *pgxpool.Pool
	// Redis backs the ephemeral store, namespaced by Ephemeral.KeyPrefix
	// (#307). Nil selects the per-process memory store, which construction
	// refuses unless Config.Ephemeral.AllowMemory is set (#305).
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
	InstanceAdmission func(ctx context.Context, persona, instanceSlug, subject string) error
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

func (s *Service) applyDeps(d Deps) {
	s.pg = d.Postgres
	if d.Postgres != nil {
		s.q = db.New(db.ForSchema(d.Postgres, s.dbSchema()))
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
}
