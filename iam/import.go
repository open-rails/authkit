package iam

import "time"

// Bulk import of accounts and legacy identities, for migrations. Every import
// operation is operator-only.

// HashAlgoLegacyResetRequired marks a migrated password that can never verify
// (DES crypt, md5-crypt, corrupted values). The raw hash is kept for forensics
// only; the account must reset its password.
const HashAlgoLegacyResetRequired = "legacy-reset-required"

// ImportUser is one account to import. It finds an existing account by ID,
// Email, Phone or Username (canonical or a live alias); ImportOptions decides
// what happens then.
type ImportUser struct {
	// ID, when set, is the new account's id, or the existing account a Merge
	// updates. It must be a UUID.
	ID            string
	Email         string
	Phone         string
	Username      string
	EmailVerified bool
	PhoneVerified bool
	// PasswordHash is an argon2id or bcrypt hash named by HashAlgo, validated
	// before it is stored. HashAlgoLegacyResetRequired keeps any value and makes
	// the account reset its password.
	PasswordHash string
	HashAlgo     string
	BannedAt     *time.Time
	BannedUntil  *time.Time
	BanReason    string
	Metadata     map[string]any
	CreatedAt    *time.Time
	UpdatedAt    *time.Time
	LastLogin    *time.Time
	// PreferredLanguage and AvatarURL are validated as UpdateUser validates them.
	PreferredLanguage string
	AvatarURL         string
	// DeletedAt, not in the future, imports the account as the operator's
	// DeleteUsers at that time would have left it: OnSoftDelete runs, the
	// 30-day recovery window runs from DeletedAt (RestoreUsers restores it,
	// signing in does not), and once the window has passed the account is
	// purged after OnHardDelete. Such rows need River, as DeleteUsers does.
	DeletedAt *time.Time
	// Providers are external identities the account signs in with, linked as
	// LinkProvider links them, at most one per issuer; Solana wallets import
	// only through ImportSolanaLinks. A row naming an identity another account
	// holds, or an earlier row of the batch names, is rejected with
	// "provider_already_linked".
	Providers []ProviderLink
}

// ImportConflict is what ImportUsers does with a row that finds an account.
type ImportConflict string

const (
	// ImportSkip leaves the account unchanged. It is the default.
	ImportSkip ImportConflict = "skip"
	// ImportMerge updates an account the row is bound to: found by ID, or by an
	// email or phone verified on the account. It merges Metadata, keeps the
	// earlier CreatedAt and the later LastLogin, and fills a PreferredLanguage
	// or AvatarURL the account lacks. Only a row bound by ID or by a contact
	// verified on both sides links Providers, and stores PasswordHash when the
	// account has no password. It never changes identity, contacts,
	// verification, bans or deletion. A row that is not bound is skipped with
	// Reason "unbound_match".
	ImportMerge ImportConflict = "merge"
)

// ImportOptions tunes ImportUsers.
type ImportOptions struct {
	OnConflict ImportConflict
}

// ImportStatus is one row's outcome.
type ImportStatus string

const (
	ImportInserted ImportStatus = "inserted"
	ImportSkipped  ImportStatus = "skipped"
	ImportMerged   ImportStatus = "merged"
	ImportRejected ImportStatus = "rejected"
)

// ImportMatch names the identifier that found an existing account, the first
// of id, email, phone and username that did.
type ImportMatch string

const (
	ImportMatchID       ImportMatch = "id"
	ImportMatchEmail    ImportMatch = "email"
	ImportMatchPhone    ImportMatch = "phone"
	ImportMatchUsername ImportMatch = "username"
)

// ImportRow is one row's outcome. Every row but a rejected one has UserID;
// skipped and merged rows say which identifier found the account. Reason
// explains skipped and rejected rows: "already_exists", "duplicate_in_batch",
// "unbound_match", "deleted", "identifier_conflict", "username_unavailable",
// "provider_already_linked", "provider_change_requires_unlink", or a
// validation code such as "invalid_provider" or "invalid_deleted_at".
type ImportRow struct {
	Index     int
	UserID    string
	MatchedBy ImportMatch
	Status    ImportStatus
	Reason    string
}

// ImportResult reports every row, in input order.
type ImportResult struct {
	Rows     []ImportRow
	Inserted int
	Skipped  int
	Merged   int
	Rejected int
}

// ImportSolanaLink reserves a legacy wallet address for an account. It is not
// a login method until the owner proves the wallet through Sign-In with Solana.
type ImportSolanaLink struct {
	UserID          string
	Address         string
	Source          string
	SourceID        string
	SourceCreatedAt *time.Time
}

// ImportSolanaLinkRow is one wallet row's outcome: inserted, skipped or
// rejected.
type ImportSolanaLinkRow struct {
	Index   int
	UserID  string
	Address string
	Status  ImportStatus
	Reason  string
}

// ImportSolanaLinksResult reports every wallet row, in input order.
type ImportSolanaLinksResult struct {
	Rows     []ImportSolanaLinkRow
	Inserted int
	Skipped  int
	Rejected int
}

// ProviderLink is an external identity to sign in with: the provider's issuer
// and subject, its configured name, and the email it reported.
type ProviderLink struct {
	Issuer   string
	Subject  string
	Provider string
	Email    string
}
