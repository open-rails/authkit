package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
)

// SessionRevokeReason identifies why a session (or set of sessions) was revoked.
type SessionRevokeReason string

// AuthSessionEvent is a best-effort, append-only session lifecycle record
// stored in Postgres (session_events, #245) and retained per
// Config.SessionEventRetention. issuer/user_id/session_id/event are required;
// method is typically set for SessionEventCreated and reason for
// SessionEventRevoked.
type AuthSessionEvent struct {
	OccurredAt time.Time
	Issuer     string
	UserID     string
	SessionID  string
	Event      iam.SessionEventKind
	Method     *string
	Reason     *string
	IPAddr     *string
	UserAgent  *string
}

const (
	SessionRevokeReasonLogout               SessionRevokeReason = "logout"
	SessionRevokeReasonUserRevoke           SessionRevokeReason = "user_revoke"
	SessionRevokeReasonUserRevokeAll        SessionRevokeReason = "user_revoke_all"
	SessionRevokeReasonAdminRevoke          SessionRevokeReason = "admin_revoke"
	SessionRevokeReasonAdminRevokeAll       SessionRevokeReason = "admin_revoke_all"
	SessionRevokeReasonPasswordChange       SessionRevokeReason = "password_change"
	SessionRevokeReasonAdminSetPassword     SessionRevokeReason = "admin_set_password"
	SessionRevokeReasonContactChange        SessionRevokeReason = "contact_change"
	SessionRevokeReasonContactProven        SessionRevokeReason = "contact_proven"
	SessionRevokeReasonMFAReset             SessionRevokeReason = "mfa_reset"
	SessionRevokeReasonBanned               SessionRevokeReason = "banned"
	SessionRevokeReasonSoftDeleted          SessionRevokeReason = "soft_deleted"
	SessionRevokeReasonEvicted              SessionRevokeReason = "evicted"
	SessionRevokeReasonRefreshReuseDetected SessionRevokeReason = "refresh_reuse_detected"
)
