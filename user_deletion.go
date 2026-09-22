package authkit

import "time"

// UserDeletion identifies one recoverable account-deletion generation.
// Hooks are delivered at least once. Use ID together with the hook name as an
// idempotency key; deleting again after restoration creates a new ID.
type UserDeletion struct {
	ID        string
	UserID    string
	DeletedAt time.Time
	PurgeAt   time.Time
}

// UserRecoveryPeriod is the fixed interval in which an accepted account
// deletion can be restored. Repeated deletion does not extend it.
const UserRecoveryPeriod = 30 * 24 * time.Hour
