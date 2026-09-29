package httpapi

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// sessionsBackend is session, token and device-key management.
type sessionsBackend interface {
	MintSessionAccessToken(ctx context.Context, userID, sessionID string) (string, time.Time, error)
	RevokeAccountSessions(ctx context.Context, a iam.Actor, userID string) (iam.AccountSessionRevocation, error)
	ListDeviceKeys(ctx context.Context, userID, currentID string) ([]authflow.DeviceKey, error)
	ListSessionEvents(ctx context.Context, userID string, eventTypes ...authflow.SessionEventType) ([]authflow.AuthSessionEvent, error)
	ListUserSessions(ctx context.Context, userID string) ([]authflow.Session, error)
	RevokeDeviceKey(ctx context.Context, userID, currentID, targetID string) error
	RevokeIssuerSessions(ctx context.Context, userID string, keepSessionID *string) error
	RevokeOtherDeviceKeys(ctx context.Context, userID, currentID string) error
	RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error
}
