package authcore

import "time"

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

// AuthSessionEvent is a best-effort, append-only session lifecycle record
// stored in Postgres (profiles.session_events, #245) and retained per
// Config.SessionEventRetention. issuer/user_id/session_id/event are required;
// method is typically set for SessionEventCreated and reason for
// SessionEventRevoked.
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
