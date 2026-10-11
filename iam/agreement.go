package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// Agreement is one document at one version (Config.Agreements): what a user
// accepts, and what agreement_required and agreements_due name.
type Agreement struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// AgreementAcceptance is a user's acceptance of one version of a document.
// Acceptances are append-only: an earlier version's stays recorded.
type AgreementAcceptance struct {
	Key        string           `json:"key"`
	Version    string           `json:"version"`
	AcceptedAt time.Time        `json:"accepted_at"`
	Channel    AgreementChannel `json:"channel"`
}

// AgreementChannel is where an acceptance was given.
type AgreementChannel string

const (
	// AgreementAtRegistration: accepted to create the account.
	AgreementAtRegistration AgreementChannel = "registration"
	// AgreementInAccount: the user accepted while signed in (account
	// settings, a sign-in's agreements_due, an OAuth client's approval).
	AgreementInAccount AgreementChannel = "account"
	// AgreementByHost: the host recorded it (Client.AcceptAgreements).
	AgreementByHost AgreementChannel = "host"
)

// AgreementRef names one version of a document a user accepts.
type AgreementRef struct {
	Key     string `json:"key"`
	Version string `json:"version"`
}

// ErrAgreementRequired refuses a sign-up, or an OAuth client's approval, that
// lacks the current version of a required agreement; its metadata names
// them (agreements: [{key, version, url}]).
var ErrAgreementRequired Error = errmodel.E(errmodel.CodeAgreementRequired)

// RefuseDeletion is what Deps.DeletionCheck returns to refuse an account's
// own deletion: deletion_refused (409), with reason, a stable code the host's
// interface explains, as metadata.reason.
func RefuseDeletion(reason string) error {
	return errmodel.E(errmodel.CodeDeletionRefused, errmodel.WithDetails(errmodel.DeletionRefusal{Reason: reason}))
}

// ErrDeletionRefused matches every RefuseDeletion error.
var ErrDeletionRefused Error = errmodel.E(errmodel.CodeDeletionRefused)
