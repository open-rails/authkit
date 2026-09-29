package authhttp

import (
	"context"
	"net"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Transport tests need private workflow setup. Capture it only in the trusted
// constructor hook, never by adding accessors to the public Runtime or Client.
type fixtureEngine interface {
	authkit.HTTPBackend
	documents.Signer
	DocumentStore() documents.Store
	StartTOTPEnrollment(ctx context.Context, userID string) (secret, otpauthURI string, err error)
	EnableTOTP2FA(ctx context.Context, in authkit.TOTPEnrollment) ([]string, error)
	ConfirmEmailChange(ctx context.Context, userID, email, code string, keepSessionID *string) error
	IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error)
	IssueRefreshSessionWithAuthMethods(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string) (sessionID, refreshToken string, expiresAt *time.Time, err error)
	IssueAuthenticatedSession(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string, extra map[string]any) (string, string, string, time.Time, *time.Time, error)
	SeedPermissionGroupContainment(ctx context.Context) error
	EnsureRootGroup(ctx context.Context) (string, error)
	AssignGroupRole(ctx context.Context, group iam.GroupRef, subject iam.Subject, role iam.Role) error
	AssignGroupRoleGenesis(ctx context.Context, group iam.GroupRef, subject iam.Subject, role iam.Role) error
	Enable2FA(ctx context.Context, userID, method string, phoneNumber *string, mode authkit.FactorEnrollmentMode) ([]string, error)
	List2FAFactors(ctx context.Context, userID string) ([]authkit.TwoFactorFactor, error)
}
type testRuntime struct {
	*authkit.Runtime
	fixtureEngine
}
type captureBackend struct{ backend fixtureEngine }

func (c *captureBackend) BuildHTTP(b authkit.HTTPBackend) (authkit.HTTPSurface, error) {
	c.backend = b.(fixtureEngine)
	return fixtureSurface{}, nil
}

type fixtureSurface struct{}

func (fixtureSurface) Routes() []authkit.HTTPRoute { return nil }
func (fixtureSurface) Verifier() *verify.Verifier  { return nil }
func (fixtureSurface) Close()                      {}
func newTestRuntime(cfg authkit.Config, deps authkit.Deps) (*testRuntime, error) {
	capture := &captureBackend{}
	cfg.HTTP = capture
	r, err := authkit.New(cfg, deps)
	if err != nil {
		return nil, err
	}
	return &testRuntime{Runtime: r, fixtureEngine: capture.backend}, nil
}
func fixtureBackend(b authkit.HTTPBackend) fixtureEngine { return b.(fixtureEngine) }
func newTestService(r *testRuntime, cfg Config) (*Service, error) {
	return New(r.fixtureEngine, cfg)
}
