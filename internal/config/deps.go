package config

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
	"github.com/open-rails/authkit/verify"
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

	// KeySource signs and publishes tokens: keys.Watch(dir) serves a key
	// directory's keys.json and totp.key (keys.TOTPSource, the TOTP key; TOTP
	// is unavailable without one). A source with no active signer only
	// verifies: minting returns iam.ErrSigningNotConfigured. Nil watches
	// /vault/auth, or for a loopback Issuer a per-issuer development
	// directory, $XDG_STATE_HOME/authkit/development/<issuer SHA-256>, where
	// AuthKit generates what is missing, marked as development keys that no
	// other issuer loads. Hosts never handle the private key: they hand
	// AuthKit a source that signs.
	KeySource keys.Source
	// Providers are the external identity providers: provider.Google,
	// Apple, Discord and GitHub, or provider.OIDC and OAuth2 for any other.
	Providers []provider.Provider

	// Email delivers email; adapters/logsender's logs it, for development.
	// Nil means no email: flows that need one answer email_unavailable. Start
	// runs its CheckHealth now and every five minutes; after two failed
	// checks in a row, email flows are unavailable until a check passes
	// (Client.EmailAvailable).
	Email EmailSender
	// SMS delivers text messages, like Email (Client.SMSAvailable).
	SMS SMSSender
	// Captcha checks the bot challenge a browser solves before a start that
	// texts or emails a code to an address it names (/passwordless/start,
	// /register): adapters/captcha.New. Nil asks for none.
	Captcha CaptchaVerifier

	// Entitlements returns the names of users' active entitlements (billing
	// tiers), keyed by user id; ids without any are absent. Admin views show
	// them all; Config.Token.EntitlementAllowlist selects which go into access
	// tokens.
	Entitlements func(ctx context.Context, userIDs []string) (map[string][]string, error)
	// EntitlementHolders returns the ids of the users who hold entitlement,
	// for ListUsers' Entitlement filter. Nil makes that filter fail with
	// iam.ErrEntitlementFilterUnavailable.
	EntitlementHolders func(ctx context.Context, entitlement string) ([]string, error)

	// OnPurge erases the host's data of a deleted account before AuthKit
	// purges the account, 30 days after its deletion. Every issuer's daily
	// startup/catch-up sweep runs its own pending cleanup receipts, and the
	// purge waits until all required issuers succeed. A failed callback stays
	// due for that issuer's next sweep. It must be idempotent and honor cancellation.
	OnPurge func(context.Context, iam.UserDeletion) error
	// DeletionCheck runs before a user deletes their own account: an
	// iam.RefuseDeletion error refuses it with deletion_refused (409, the
	// reason in metadata.reason), such as while the user's cards still pay
	// subscriptions; any other error fails the request. Deleting someone
	// else's account (staff, the host) does not run it.
	DeletionCheck func(ctx context.Context, userID string) error
	// ConsentRevocationCheck runs before a user withdraws their own consent
	// to a group OAuth client: an iam.RefuseConsentRevocation error refuses
	// it with consent_revocation_refused (409, metadata.reason), such as
	// while the link it made still pays subscriptions; any other error
	// fails the request. Client.RevokeConsent does not run it.
	ConsentRevocationCheck func(ctx context.Context, userID, clientID string) error
	// PasskeyTopOrigin admits passkey ceremonies inside a cross-origin
	// iframe of Passkeys.Origins, as on a merchant's site embedding the
	// host's sign-in: a ceremony whose client data names the framing page
	// (topOrigin, an https origin) passes when it reports true, and one that
	// names none (Safari) passes on its own origin. Nil refuses every
	// ceremony in a cross-origin iframe. An error fails the ceremony.
	PasskeyTopOrigin func(ctx context.Context, topOrigin string) (bool, error)
	// GroupName is a group's name, as the host knows it (a merchant's
	// verified name): the consent screen and a user's connected apps show it
	// beside a group OAuth client's own name. Nil shows the client's alone.
	GroupName func(ctx context.Context, groupID string) (string, error)

	// OAuthGrants decides each jwt-bearer grant of the authorization
	// server: it may refuse or narrow a workload's capability. Required
	// when a client declares AuthorizationDetailsTypes, as every jwt-bearer
	// client does.
	OAuthGrants iam.OAuthGrantAuthorizer
	// NameAdmission is the host's side-effect-free username policy for
	// account creation and renames; an error refuses the name.
	NameAdmission func(context.Context, iam.NameAdmissionRequest) error

	// Redis shares rate-limit counters and spent DPoP proofs across
	// replicas; it holds no other AuthKit state. Without it, and while it
	// fails, each process keeps its own: one node only.
	Redis redis.UniversalClient
	// Replays spends DPoP proofs and JWT-bearer and client assertions for
	// every replica, in place of Redis or memory: a host with more than one
	// replica and no Redis implements it on the store they share. Its errors
	// refuse the proof. Rate limits stay with Redis or memory.
	Replays verify.ReplayStore
	// ResourceHosts admits hosts besides Config.Resource.PublicURL's that the
	// resource answers on (a host's per-tenant API hosts): a DPoP proof's htu
	// may name https://<host> when it reports true for the request's Host.
	// No header is trusted otherwise.
	ResourceHosts func(ctx context.Context, host string) (bool, error)
	// SCIMHandlers serve in-process SCIM service providers, keyed by the
	// name of the Config.Provisioning target they serve (one without a URL),
	// so an embedded service provider is called with no network. Requests
	// reach a handler with paths relative to its base ("/Users", "/Bulk").
	SCIMHandlers map[string]http.Handler
	// ClientIP extracts the client address. It is the host's own client-IP
	// posture: New refuses it beside HTTPConfig's proxies or DirectPeerIP.
	ClientIP func(*http.Request) string
	// RequestClient names the app or merchant a request comes through, such
	// as the merchant whose checkout embeds the sign-in: every text message
	// it triggers spends that client's sms_client budget. It must name only
	// what the host trusts; "" (or nil) spends none.
	RequestClient func(*http.Request) string
	// RequestTenant selects an existing native account directory before HTTP
	// guards consume credentials, sender proofs or rate limits. It must resolve
	// only host-trusted assignments; request headers alone grant no authority.
	// Zero preserves the default directory (or a ForTenant view's fixed target).
	// A nonzero selection cannot change a ForTenant view's target. Errors fail
	// closed; auth.ErrForbidden refuses selection with 403. Nil keeps the
	// existing dispatch behavior. The original URL and headers are preserved.
	RequestTenant func(*http.Request) (iam.TenantID, error)
	// Wrap decorates every API and browser-OIDC handler at mount time, inside
	// the request guards. Use RequestTenant for directory selection.
	Wrap func(iam.Route, http.Handler) http.Handler

	// Logger receives everything AuthKit logs, its River clients' and
	// migrators' included. Nil is slog.Default(), read once by New; AuthKit
	// never changes the default. What the host builds, and the functions that
	// need no Client, take their own: keys.Watch, provider.WithLogger,
	// verify.WithLogger, twilio.SMSConfig.Logger, MigrationOptions.Logger,
	// EnsureGroups, NewNotificationDelivery and
	// ParseBootstrapManifestYAML.
	Logger *slog.Logger
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
	// Send delivers msg. A number it or its provider will not text is
	// iam.RefuseSMSDestination: that number's answer, not the sender's
	// health.
	Send(ctx context.Context, msg iam.SMSMessage) error
	// CheckHealth reports, without sending, whether messages can be delivered
	// now: nil when healthy, or when the provider can't tell.
	CheckHealth(ctx context.Context) error
}

// CaptchaVerifier checks bot challenges; adapters/captcha.New returns one.
type CaptchaVerifier interface {
	// Widget is what the browser renders: the provider and its site key.
	Widget() iam.CaptchaWidget
	// Verify checks the token the widget gave, solved at remoteIP; a token
	// passes once. A refused token is iam.ErrCaptchaFailed; any other error
	// means the provider could not tell.
	Verify(ctx context.Context, token, remoteIP string) error
}
