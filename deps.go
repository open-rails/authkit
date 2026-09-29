package authkit

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/iam"
)

// Deps are the runtime dependencies New builds Auth with. Config carries
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
	OnSoftDelete func(context.Context, iam.UserDeletion) error
	OnHardDelete func(context.Context, iam.UserDeletion) error
	OnRestore    func(context.Context, iam.UserDeletion) error
	// DelegatedAuthorization is the host's delegation authorizer for the
	// delegated-token mint route (#261/#277); its grant is the complete
	// authority AuthKit signs. Required when Delegated.Audiences is set.
	DelegatedAuthorization iam.DelegationAuthorizer
	// ApplicationAdmission is consulted before any application
	// self-registration fetch (#264): a non-nil error refuses the attempt.
	ApplicationAdmission func(ctx context.Context, domain string) error
	// InstanceAdmission is consulted before any generated persona-instance
	// creation (#263) with the normalized slug; a non-nil error refuses.
	InstanceAdmission func(ctx context.Context, group iam.GroupRef, subject string) error
	// NameAdmission is the host's side-effect-free namespace policy for
	// creation and rename.
	NameAdmission func(context.Context, iam.NameAdmissionRequest) error
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

// RiverOwnership declares who initializes and runs River. Nil means AuthKit
// owns its client. Use RiverFromHost for a fleet shared with other libraries.
// Pass the same declaration to Deps and MigrateOptions.
type RiverOwnership struct{ fromHost bool }

// RiverFromHost selects a host-owned River fleet. AuthKit never migrates,
// starts, or stops it. Pass RiverJobs() to riverhelpers.New to register AuthKit's
// workers and schedules in the host fleet.
func RiverFromHost() *RiverOwnership { return &RiverOwnership{fromHost: true} }

// EmailSender sends verification/login/reset/notice emails.
type EmailSender interface {
	SendVerification(ctx context.Context, email, username string, msg iam.VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, email, username, resetURL string) error
	SendAccountRegistrationInvite(ctx context.Context, email, inviteURL string) error
	SendLoginCode(ctx context.Context, email, username, code string) error
	SendWelcome(ctx context.Context, email, username string) error
	// SendContactChanged goes to the address that was just REPLACED.
	SendContactChanged(ctx context.Context, email, username string, change iam.ContactChange) error
	// SendDeviceKeyEnrolled tells the account's address that a new device key
	// can now sign in as it.
	SendDeviceKeyEnrolled(ctx context.Context, email, username string, notice iam.DeviceKeyNotice) error
	// SendMFAReset tells the account's address that the operator removed its
	// passkeys, second factors and device keys and signed it out everywhere.
	SendMFAReset(ctx context.Context, email, username string) error
}

// SMSSender sends verification/login/reset/notice SMS messages.
type SMSSender interface {
	SendVerification(ctx context.Context, phone string, msg iam.VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, phone, resetURL string) error
	SendLoginCode(ctx context.Context, phone, code string) error
	// SendContactChanged goes to the number that was just REPLACED.
	SendContactChanged(ctx context.Context, phone string, change iam.ContactChange) error
}

// SMSHealthChecker is an optional capability for SMS senders that can verify,
// without sending a message, that they are configured to actually deliver
// (valid credentials, an attached sender, and a verified/registered number).
// CheckHealth returns nil when delivery is expected to succeed, or a
// descriptive error explaining why it will not (e.g. an unverified toll-free
// sender that would otherwise fail silently with Twilio error 30032).
type SMSHealthChecker interface {
	CheckHealth(ctx context.Context) error
}

// EntitlementsProvider returns the names of users' currently active
// application entitlements (e.g., billing tiers). Names are the ONLY shape
// AuthKit consumes. Token.EntitlementAllowlist selects which names may appear
// in access tokens; admin user views receive the full result. Providers return
// active grants only; expired/revoked entitlements are the provider's concern,
// not AuthKit's.
//
// One call answers many users: the map is keyed by user id and unknown or
// entitlement-less ids are absent. A single-user read is a one-element batch.
type EntitlementsProvider interface {
	ListEntitlements(ctx context.Context, userIDs []string) (map[string][]string, error)
}

// EntitlementFilterProvider is the REVERSE of EntitlementsProvider: given an
// entitlement key, it returns the subject ids that currently hold it. AuthKit
// owns the user DIRECTORY; the billing system (OpenRails) owns "who is entitled",
// so filtering the directory BY entitlement delegates here instead of joining
// across schemas. Subject ids ARE user ids (UUID-only payable identity). Detected
// by type assertion on the entitlements provider; when absent, ListUsers with
// an Entitlement filter fails with ErrEntitlementFilterUnavailable so the
// misconfiguration is loud rather than silently returning everyone.
type EntitlementFilterProvider interface {
	ListSubjectsWithEntitlement(ctx context.Context, entitlement string) ([]string, error)
}

// SolanaSNSResolver resolves a wallet's primary SNS name after a verified link.
// The default talks to the public sdk-proxy; Deps.SolanaSNSResolver replaces
// it.
type SolanaSNSResolver interface {
	ResolvePrimaryName(ctx context.Context, address string) (string, error)
}
