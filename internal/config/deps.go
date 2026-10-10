package config

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
)

// Deps is everything AuthKit reaches outside the process through: the store,
// keys, identity providers, senders and the host's hooks. Senders are
// provider objects; every hook is a func, so bind one late with a closure
// when it needs the Client first.
type Deps struct {
	// Postgres is the durable store, required by every host-facing
	// constructor. New creates or upgrades AuthKit's and River's tables
	// through it, so its role owns and uses them. It also holds AuthKit's
	// short-lived auth state (codes, ceremonies, attempt counters), shared by
	// every replica.
	Postgres *pgxpool.Pool

	// KeySource signs and publishes tokens. Nil resolves keys from
	// Config.Keys. Hosts never handle the private key: they hand AuthKit a
	// source that signs.
	KeySource keys.Source
	// Providers are the external identity providers: provider.Google,
	// Apple, Discord and GitHub, or provider.OIDC and OAuth2 for any other.
	Providers []provider.Provider

	// Email delivers email. Nil means no email: flows that need one fail
	// unless Config.Registration.AllowMissingSenders is set. Start runs its
	// CheckHealth now and every Config.SenderHealthInterval; while it fails,
	// email flows are unavailable (Client.EmailAvailable).
	Email EmailSender
	// SMS delivers text messages, like Email (Client.SMSAvailable).
	SMS SMSSender

	// Entitlements returns the names of users' active entitlements (billing
	// tiers), keyed by user id; ids without any are absent. Admin views show
	// them all; Config.Token.EntitlementAllowlist selects which go into access
	// tokens.
	Entitlements func(ctx context.Context, userIDs []string) (map[string][]string, error)
	// EntitlementHolders returns the ids of the users who hold entitlement,
	// for ListUsers' Entitlement filter. Nil makes that filter fail with
	// iam.ErrEntitlementFilterUnavailable.
	EntitlementHolders func(ctx context.Context, entitlement string) ([]string, error)

	// OnEvent receives account and group changes (iam.Event) durably through
	// River: recorded in the change's transaction, delivered after commit at
	// least once, in order per user (per group for group events). A failure
	// is retried with backoff up to an hour apart and holds back that
	// subject's later events. It must be idempotent on Event.ID, ignore kinds
	// it does not know and never run in the change's transaction. Every
	// account issuer with OnEvent receives the account events. Building a
	// client with OnEvent subscribes its issuer: changes are recorded from
	// then on, even while no fleet runs. Clients without it change nothing
	// until one starts the issuer's fleet: that unsubscribes the issuer, and
	// its fleet drains what is pending.
	OnEvent func(context.Context, iam.Event) error
	// OnPurge erases the host's data of a deleted account before AuthKit
	// purges the account, 30 days after its deletion. It runs durably through
	// River on every account issuer, and the purge waits until each has
	// succeeded; a failure is retried. It must be idempotent and honor
	// cancellation.
	OnPurge func(context.Context, iam.UserDeletion) error

	// OAuthGrants decides each jwt-bearer grant of the authorization
	// server: it may refuse or narrow a workload's capability. Required
	// when a client declares AuthorizationDetailsTypes, as every jwt-bearer
	// client does.
	OAuthGrants iam.OAuthGrantAuthorizer
	// NameAdmission is the host's side-effect-free username policy for
	// account creation and renames; an error refuses the name.
	NameAdmission func(context.Context, iam.NameAdmissionRequest) error

	// Redis shares rate-limit counters across replicas; it holds no other
	// AuthKit state. Without it, and while it fails, each process counts on
	// its own with the same limits.
	Redis redis.UniversalClient
	// ClientIP extracts the client address, replacing the proxy handling of
	// HTTPConfig.
	ClientIP func(*http.Request) string
	// Wrap decorates every API and browser-OIDC handler at mount time.
	Wrap func(iam.Route, http.Handler) http.Handler
}

// EmailSender delivers email; adapters/smtp.New returns one.
type EmailSender interface {
	Send(ctx context.Context, msg iam.EmailMessage) error
	// CheckHealth reports, without sending, whether email can be delivered
	// now: nil when healthy, or when the provider can't tell.
	CheckHealth(ctx context.Context) error
}

// SMSSender delivers text messages; adapters/twilio.NewSMS returns one.
type SMSSender interface {
	Send(ctx context.Context, msg iam.SMSMessage) error
	// CheckHealth reports, without sending, whether messages can be delivered
	// now: nil when healthy, or when the provider can't tell.
	CheckHealth(ctx context.Context) error
}
