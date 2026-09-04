package authkit

import (
	"fmt"
	"time"
)

// FormerNameRetentionMode controls reservation and forwarding after a rename.
type FormerNameRetentionMode string

const (
	FormerNamesFinite          FormerNameRetentionMode = "finite"
	FormerNamesForever         FormerNameRetentionMode = "forever"
	FormerNamesImmediate       FormerNameRetentionMode = "immediate"
	DefaultRenameInterval                              = 72 * time.Hour
	DefaultFormerNameRetention                         = 90 * 24 * time.Hour
)

// NamingConfig is deployment-wide policy for users and group instances. Pointers
// distinguish omission (defaults) from explicit false/zero. Durations use Go's
// time.Duration in embedded configuration; the standalone boundary parses text.
type NamingConfig struct {
	Enabled        *bool                     `json:"enabled,omitempty"`
	RenameInterval *time.Duration            `json:"rename_interval,omitempty"`
	FormerNames    FormerNameRetentionConfig `json:"former_names,omitempty"`
}

type FormerNameRetentionConfig struct {
	Mode     FormerNameRetentionMode `json:"mode,omitempty"`
	Duration *time.Duration          `json:"duration,omitempty"`
}

// NamingPolicy is the validated, immutable value used by both identity kinds.
// Duration values in JSON are nanoseconds, as for time.Duration in Go.
type NamingPolicy struct {
	Enabled                 bool                    `json:"enabled"`
	RenameInterval          time.Duration           `json:"rename_interval"`
	FormerNameRetentionMode FormerNameRetentionMode `json:"former_name_retention_mode"`
	FormerNameRetention     time.Duration           `json:"former_name_retention"`
}

// Normalize validates once at the configuration boundary. An empty retention
// object or finite-without-duration selects 90 days. Duration-without-mode means
// finite; finite zero means immediate. Other modes cannot specify a duration.
func (c NamingConfig) Normalize() (NamingPolicy, error) {
	p := NamingPolicy{Enabled: true, RenameInterval: DefaultRenameInterval,
		FormerNameRetentionMode: FormerNamesFinite, FormerNameRetention: DefaultFormerNameRetention}
	if c.Enabled != nil {
		p.Enabled = *c.Enabled
	}
	if c.RenameInterval != nil {
		p.RenameInterval = *c.RenameInterval
	}
	if p.RenameInterval < 0 {
		return NamingPolicy{}, fmt.Errorf("naming.rename_interval must be nonnegative")
	}
	if c.FormerNames.Mode != "" {
		p.FormerNameRetentionMode = c.FormerNames.Mode
	}
	switch p.FormerNameRetentionMode {
	case FormerNamesFinite:
		if c.FormerNames.Duration != nil {
			p.FormerNameRetention = *c.FormerNames.Duration
		}
		if p.FormerNameRetention < 0 {
			return NamingPolicy{}, fmt.Errorf("naming.former_names.duration must be nonnegative")
		}
		if p.FormerNameRetention == 0 {
			p.FormerNameRetentionMode = FormerNamesImmediate
		}
	case FormerNamesForever, FormerNamesImmediate:
		if c.FormerNames.Duration != nil {
			return NamingPolicy{}, fmt.Errorf("naming.former_names.duration requires finite retention")
		}
		p.FormerNameRetention = 0
	default:
		return NamingPolicy{}, fmt.Errorf("invalid naming.former_names.mode %q", p.FormerNameRetentionMode)
	}
	return p, nil
}

// CheckRename is shared by user/group mutations under their owner lock. Callers
// authorize and detect a same-canonical-name no-op before checking this policy.
// Trusted import updates skip this check, never namespace ownership checks.
func (p NamingPolicy) CheckRename(lastRenamedAt *time.Time, now time.Time) error {
	if !p.Enabled {
		return ErrRenamesDisabled
	}
	if lastRenamedAt != nil {
		next := lastRenamedAt.Add(p.RenameInterval)
		if now.Before(next) {
			return &RenameCooldownError{NextRenameAt: next}
		}
	}
	return nil
}

// FormerNameExpiresAt captures the promise made at rename time. Nil means
// forever. Immediate returns now: request-time lookup/claim use the same strict
// now.Before(deadline) boundary. Later policy changes never rewrite this value.
func (p NamingPolicy) FormerNameExpiresAt(now time.Time) *time.Time {
	if p.FormerNameRetentionMode == FormerNamesForever {
		return nil
	}
	deadline := now.Add(p.FormerNameRetention)
	return &deadline
}

type RenameCooldownError struct {
	NextRenameAt time.Time `json:"next_rename_at"`
}

func (e *RenameCooldownError) Error() string { return ErrRenameRateLimited.Error() }
func (e *RenameCooldownError) Unwrap() error { return ErrRenameRateLimited }

// NameResolution always addresses one immutable owner. An alias points directly
// to that owner; CanonicalName reflects its current spelling, never an alias chain.
// AliasExpiresAt is nil for canonical names and permanent aliases; IsAlias tells
// them apart. Expired aliases are not resolutions.
type NameResolution struct {
	ID             string     `json:"id"`
	CanonicalName  string     `json:"canonical_name"`
	IsAlias        bool       `json:"is_alias"`
	AliasExpiresAt *time.Time `json:"alias_expires_at,omitempty"`
}

// GroupInstanceUpdate changes group settings atomically against a captured UUID.
type GroupInstanceUpdate struct {
	Slug        *string `json:"slug,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
}

type NameAlias struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type NamingState struct {
	Aliases           []NameAlias  `json:"aliases,omitempty"`
	Policy            NamingPolicy `json:"policy"`
	Allowed           bool         `json:"allowed"`
	NextRenameAt      *time.Time   `json:"next_rename_at,omitempty"`
	RetryAfterSeconds int64        `json:"retry_after_seconds"`
}

func (p NamingPolicy) State(last *time.Time, now time.Time) NamingState {
	out := NamingState{Policy: p, Allowed: p.Enabled}
	if last != nil {
		next := last.Add(p.RenameInterval)
		out.NextRenameAt = &next
		if next.After(now) {
			out.Allowed = false
			remaining := next.Sub(now)
			out.RetryAfterSeconds = int64(remaining / time.Second)
			if remaining%time.Second != 0 {
				out.RetryAfterSeconds++
			}
		}
	}
	return out
}

// NameAdmissionRequest is the namespace admission hook's operation context.
// Group creation cost/enrollment hooks remain creation-only.
type NameAdmissionRequest struct {
	OwnerKind     string
	Persona       string
	OwnerID       string // Empty only before a new group/account is created.
	ActorID       string
	CurrentName   string
	RequestedName string
	Operation     NameOperation
}
type NameOperation string

const (
	NameCreate NameOperation = "create"
	NameRename NameOperation = "rename"
)
