package iam

import "errors"

// ErrGroupPersonaMigration refuses an unsafe or incomplete explicit mapping.
var ErrGroupPersonaMigration = errors.New("authkit: group persona migration refused")

// ErrGroupPersonaFingerprint means the reviewed plan or its database snapshot
// changed. Produce and review a fresh dry-run before applying it.
var ErrGroupPersonaFingerprint = errors.New("authkit: group persona migration fingerprint changed")

// EventGroupPersonaMigrated records the explicit transition, without changing
// historical grant events. Previous and Current name the old and new personas.
const EventGroupPersonaMigrated EventKind = "group.persona_migrated"

// GroupPersonaMigration is a trusted host maintenance operation, never a
// permission-granting HTTP shortcut. Both catalogs must be declared while it
// runs. Maps are explicit and one-to-one; permissions name concrete grants,
// not wildcard prefixes. No omitted or widened role is inferred.
//
// The default is a read-only dry-run. Apply requires its exact fingerprint,
// table-owner privileges, and a maintenance window: it briefly locks the
// permission-group table. Quiesce writers and deploy a compatible role catalog
// to every issuer first. Existing signed permission claims are not rewritten.
type GroupPersonaMigration struct {
	Group               GroupRef
	From                Persona
	To                  Persona
	Roles               map[Role]Role
	Permissions         map[Perm]Perm
	Apply               bool
	ExpectedFingerprint string
}

// GroupPersonaRoleChange describes the exact target grant set of one mapping.
type GroupPersonaRoleChange struct {
	From        Role   `json:"from"`
	To          Role   `json:"to"`
	Permissions []Perm `json:"permissions"`
}

// GroupPersonaMigrationReport contains no credential material, credential
// hashes, claims, or contacts.
// Fingerprint binds the snapshot, maps and both compiled permission catalogs.
// An already-target group is a validated no-op; its fingerprint is current.
type GroupPersonaMigrationReport struct {
	GroupID              string                   `json:"group_id"`
	TenantID             TenantID                 `json:"tenant_id"`
	From                 Persona                  `json:"from"`
	To                   Persona                  `json:"to"`
	Fingerprint          string                   `json:"fingerprint"`
	Applied              bool                     `json:"applied"`
	AlreadyTarget        bool                     `json:"already_target"`
	Counts               map[string]int           `json:"counts"`
	Roles                []GroupPersonaRoleChange `json:"roles"`
	Issuers              []string                 `json:"issuers"`
	RequiresTokenReissue bool                     `json:"requires_token_reissue"`
}
