package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/verify"
)

// sessionsBackend is session, token and device-key management, and the live
// session gates.
type sessionsBackend interface {
	// VerifyRequest authenticates AuthKit's own routes (verify.Authenticator).
	VerifyRequest(r *http.Request) (verify.Claims, error)
	AddMFAEnrollmentExemptRoutes(paths []string)
	CheckSession(ctx context.Context, cl verify.Claims) error
	CheckRecentSignIn(ctx context.Context, cl verify.Claims) error
	StepUpRequired(ctx context.Context, userID string) error
	MintSessionAccessToken(ctx context.Context, userID, sessionID string) (string, time.Time, error)
	RevokeAccountSessions(ctx context.Context, a iam.Actor, userID string) (iam.AccountSessionRevocation, error)
	ListDeviceKeys(ctx context.Context, userID, currentID string) ([]authflow.DeviceKey, error)
	SessionEvents(ctx context.Context, userID string, q iam.SessionEventQuery) (iam.ListPage[iam.SessionEvent], error)
	ListUserSessions(ctx context.Context, userID string) ([]authflow.Session, error)
	RevokeDeviceKey(ctx context.Context, userID, currentID, targetID string) error
	RevokeIssuerSessions(ctx context.Context, userID string, keepSessionID *string) error
	RevokeOtherDeviceKeys(ctx context.Context, userID, currentID string) error
	RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error
}
