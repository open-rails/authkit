package authkit

import (
	"context"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/httpapi"
)

// HTTP workflow tests drive the engine directly for setup the public surface
// does not offer.
type fixtureEngine interface {
	httpapi.Backend
	Postgres() *pgxpool.Pool
	Config() Config
	Schema() string
	documents.Signer
	DocumentStore() documents.Store
	StartTOTPEnrollment(ctx context.Context, userID string) (secret, otpauthURI string, err error)
	EnableTOTP2FA(ctx context.Context, in TOTPEnrollment) ([]string, error)
	ConfirmEmailChange(ctx context.Context, userID, email, code string, keepSessionID *string) error
	IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error)
	IssueRefreshSessionWithAuthMethods(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string) (sessionID, refreshToken string, expiresAt *time.Time, err error)
	IssueAuthenticatedSession(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string, extra map[string]any) (string, string, string, time.Time, *time.Time, error)
	SeedPermissionGroupContainment(ctx context.Context) error
	EnsureRootGroup(ctx context.Context) (string, error)
	AssignGroupRole(ctx context.Context, group iam.GroupRef, subject iam.Subject, role iam.Role) error
	AssignGroupRoleGenesis(ctx context.Context, group iam.GroupRef, subject iam.Subject, role iam.Role) error
	Enable2FA(ctx context.Context, userID, method string, phoneNumber *string, mode authflow.FactorEnrollmentMode) ([]string, error)
	List2FAFactors(ctx context.Context, userID string) ([]authflow.TwoFactorFactor, error)
}
type testRuntime struct {
	*Runtime
	fixtureEngine
}

func newTestRuntime(cfg Config, deps Deps) (*testRuntime, error) {
	r, err := New(cfg, deps)
	if err != nil {
		return nil, err
	}
	return &testRuntime{Runtime: r, fixtureEngine: r.engine}, nil
}
func fixtureBackend(b httpapi.Backend) fixtureEngine { return b.(fixtureEngine) }
func newTestService(r *testRuntime, cfg httpapi.Config) (*httpapi.Service, error) {
	return httpapi.New(r.fixtureEngine, r.Verifier(), cfg)
}
