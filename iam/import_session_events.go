package iam

import "time"

// ImportSessionEvent is a historical sign-in attempt for an existing account.
// Importing it creates no session and changes no account state, including LastLogin.
type ImportSessionEvent struct {
	UserID string
	// ID is the host's stable key, unique per account (1–256 bytes). Namespace
	// it by source when importing multiple systems. Reusing it never updates
	// an earlier entry, even when its issuer or other fields differ.
	ID string
	// Kind is SessionEventCreated for success or SessionEventFailed for failure.
	Kind SessionEventKind
	// OccurredAt is required and cannot be in the future.
	OccurredAt time.Time
	// Issuer defaults to Config.Token.Issuer; a host may name a legacy site
	// instead (at most 2048 bytes).
	Issuer string
	// Method or Reason must name the source; each is at most 256 bytes.
	Method string
	Reason string
	// IP is an optional literal IPv4 or IPv6 address, not inet_pton bytes.
	IP string
	// UserAgent is optional, at most 4096 bytes. All text must be UTF-8 without NUL.
	UserAgent string
}

// ImportSessionEventStatus is one history entry's outcome.
type ImportSessionEventStatus string

const (
	SessionEventImported  ImportSessionEventStatus = "imported"
	SessionEventDuplicate ImportSessionEventStatus = "duplicate"
	SessionEventRefused   ImportSessionEventStatus = "refused"
)

// ImportSessionEventReason explains a refused entry. An unknown account also
// covers accounts in another tenant, without disclosing their existence.
type ImportSessionEventReason string

const (
	SessionEventUnknownAccount ImportSessionEventReason = "unknown_account"
	SessionEventDeletedAccount ImportSessionEventReason = "deleted_account"
	SessionEventTooOld         ImportSessionEventReason = "too_old"
	SessionEventInvalid        ImportSessionEventReason = "invalid"
)

// ImportSessionEventRow reports one processed entry, by its input index.
type ImportSessionEventRow struct {
	Index  int                      `json:"index"`
	Status ImportSessionEventStatus `json:"status"`
	Reason ImportSessionEventReason `json:"reason"`
}

// ImportSessionEventsResult reports processed entries in input order. On an
// error it contains only completed entries; the rest may be retried safely.
type ImportSessionEventsResult struct {
	Rows []ImportSessionEventRow `json:"rows"`
}
