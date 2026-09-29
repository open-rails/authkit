package iam

import "time"

// BootstrapManifest is genesis seed data: accounts, their root roles and
// remote applications. ApplyBootstrapManifest applies it as a host operation;
// Client.ParseBootstrapManifestYAML reads one from its YAML file format.
type BootstrapManifest struct {
	Users              []BootstrapManifestUser
	RemoteApplications []BootstrapManifestRemoteApplication
}

// BootstrapManifestUser seeds one account. A new account is created as
// declared. An existing account is used only when the email or phone the
// manifest names is verified on it, and its identity, contacts, ban and
// metadata are left as they are. An account found any other way (unverified
// contact, or username when no contact is named) is refused unless the apply
// would change nothing on it.
type BootstrapManifestUser struct {
	Username      string
	Email         string
	Phone         string
	EmailVerified bool
	PhoneVerified bool
	Banned        bool
	BannedUntil   *time.Time
	BanReason     string
	Metadata      map[string]any
	Password      *BootstrapUserPassword
	// RootRole is the account's root role. The root owner role is seeded only
	// while the root group has no usable owner.
	RootRole Role
}

// BootstrapManifestRemoteApplication seeds one application controlled by root.
type BootstrapManifestRemoteApplication struct {
	Slug       string
	Issuer     string
	JWKSURI    string
	PublicKeys []RemoteApplicationKey
	Enabled    *bool
	RootRole   Role
}

// BootstrapUserPassword is exactly one of Plaintext, Hash with HashAlgo, or
// ResetRequired.
type BootstrapUserPassword struct {
	Plaintext     string `json:"plaintext" yaml:"plaintext"`
	Hash          string `json:"hash" yaml:"hash"`
	HashAlgo      string `json:"hash_algo" yaml:"hash_algo"`
	ResetRequired bool   `json:"reset_required" yaml:"reset_required"`
	// Enforce re-asserts the password on every apply. Without it the password
	// is set only when the account is created, so a rotated password is never
	// reverted. It cannot be combined with ResetRequired.
	Enforce bool `json:"enforce" yaml:"enforce"`
}

// BootstrapOptions tunes ApplyBootstrapManifest.
type BootstrapOptions struct {
	// DryRun validates and counts without writing.
	DryRun bool
	// StartupOnly applies the manifest at most once per database schema; leave
	// it false for host or CLI applies.
	StartupOnly bool
	// Name labels the StartupOnly receipt ("" is "default"). Another name does
	// not rerun genesis.
	Name string
}

// BootstrapResult counts what an apply did.
type BootstrapResult struct {
	DryRun                     bool `json:"dry_run"`
	AlreadyApplied             bool `json:"already_applied"`
	UsersCreated               int  `json:"users_created"`
	UsersMatched               int  `json:"users_matched"`
	PasswordsSet               int  `json:"passwords_set"`
	PasswordsKept              int  `json:"passwords_kept"`
	RootRoleAssignments        int  `json:"root_role_assignments"`
	RemoteApplications         int  `json:"remote_applications"`
	RemoteApplicationRootRoles int  `json:"remote_application_root_roles"`
}
