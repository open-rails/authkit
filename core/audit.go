package core

import (
	"context"
	"time"
)

// SessionEventType identifies a session lifecycle event.
type SessionEventType string

const (
	SessionEventCreated          SessionEventType = "session_created"
	SessionEventRevoked          SessionEventType = "session_revoked"
	SessionEventPasswordChange   SessionEventType = "password_changed"
	SessionEventPasswordRecovery SessionEventType = "password_recovery"
	SessionEventFailed           SessionEventType = "session_failed"
)

// SessionRevokeReason identifies why a session (or set of sessions) was revoked.
type SessionRevokeReason string

const (
	SessionRevokeReasonUnknown              SessionRevokeReason = ""
	SessionRevokeReasonLogout               SessionRevokeReason = "logout"
	SessionRevokeReasonUserRevoke           SessionRevokeReason = "user_revoke"
	SessionRevokeReasonUserRevokeAll        SessionRevokeReason = "user_revoke_all"
	SessionRevokeReasonAdminRevoke          SessionRevokeReason = "admin_revoke"
	SessionRevokeReasonAdminRevokeAll       SessionRevokeReason = "admin_revoke_all"
	SessionRevokeReasonPasswordChange       SessionRevokeReason = "password_change"
	SessionRevokeReasonAdminSetPassword     SessionRevokeReason = "admin_set_password"
	SessionRevokeReasonUserDisabled         SessionRevokeReason = "user_disabled"
	SessionRevokeReasonBanned               SessionRevokeReason = "banned"
	SessionRevokeReasonSoftDeleted          SessionRevokeReason = "soft_deleted"
	SessionRevokeReasonEvicted              SessionRevokeReason = "evicted"
	SessionRevokeReasonRefreshReuseDetected SessionRevokeReason = "refresh_reuse_detected"
)

// AuthSessionEvent is a best-effort, append-only session lifecycle record intended for external sinks.
//
// ClickHouse schema expectation (see migrations/clickhouse):
// - issuer, user_id, session_id, event are required
// - method is typically set for SessionEventCreated
// - reason is typically set for SessionEventRevoked
type AuthSessionEvent struct {
	OccurredAt time.Time
	Issuer     string
	UserID     string
	SessionID  string
	Event      SessionEventType
	Method     *string
	Reason     *string
	IPAddr     *string
	UserAgent  *string
}

// AuthEventLogger records authentication session lifecycle events to an external sink (e.g., ClickHouse).
// Implementations should be non-blocking and best-effort.

type AuthEventLogger interface {
	LogSessionEvent(ctx context.Context, e AuthSessionEvent) error
}

// AuthEventLogReader allows listing session events filtered by event types and optional userID.
type AuthEventLogReader interface {
	// ListSessionEvents returns session events matching any of the given event types.
	// If userID is empty, returns events for all users.
	ListSessionEvents(ctx context.Context, userID string, eventTypes ...SessionEventType) ([]AuthSessionEvent, error)
}
