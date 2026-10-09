package iam

import "time"

// ProvisioningTarget is the delivery status of one SCIM target
// (Config.Provisioning).
type ProvisioningTarget struct {
	Name string `json:"name"`
	// SyncedAt is when the initial sync queued every account; nil until then.
	SyncedAt *time.Time `json:"synced_at"`
	// ReconciledAt is when the target's users were last compared with the
	// accounts.
	ReconciledAt *time.Time `json:"reconciled_at"`
	// LastSuccessAt is when a run last delivered everything it sent.
	LastSuccessAt *time.Time `json:"last_success_at"`
	// FailingSince is when deliveries began failing; nil while none is.
	FailingSince *time.Time `json:"failing_since"`
	LastError    *string    `json:"last_error"`
	// Backlog is how many users wait to be sent, retries included.
	Backlog int `json:"backlog"`
}
