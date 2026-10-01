package iam

import "time"

// Bulk import of accounts and legacy identities, for migrations. Every import
// is a host operation: your code decides.

// ImportUser is one account to import. It finds an existing account by ID,
// Email, Phone or Username (canonical or a live alias); ImportOptions decides
// what happens then.
type ImportUser struct {
	// ID, when set, is the new account's id, or the existing account a Merge
	// updates. It must be a UUID.
	ID       string
	Email    string
	Phone    string
	Username string
	// EmailVerified and PhoneVerified are the source system's word, not proof
	// (someone may have confirmed another person's address there). They only
	// let the account sign in before proving an address. Addresses import
	// unverified, and the account is unproven until it proves one here (a
	// code or a reset link): it adds no login method or address, and its first
	// proof retires the imported credentials and other addresses (a password
	// survives only when the proving session signed in with it).
	EmailVerified bool
	PhoneVerified bool
	// PasswordHash is validated before it is stored; HashLegacyResetRequired
	// keeps any value and makes the account reset its password.
	PasswordHash *PasswordHash
	// Ban imports a ban as it stood: At is required, By (the banning
	// account) is optional.
	Ban *BanState
	// PublicMetadata is the account's public metadata (iam.PublicUser):
	// anyone may read it, so import only public fields.
	PublicMetadata map[string]any
	CreatedAt      *time.Time
	UpdatedAt      *time.Time
	LastLogin      *time.Time
	// PreferredLanguage is validated as UpdateUser validates it.
	PreferredLanguage string
	// DeletedAt, not in the future, imports the account as the system's
	// DeleteUsers at that time would have left it: the 30-day recovery window
	// runs from DeletedAt (RestoreUsers restores it, signing in does not), and
	// once the window has passed the account is purged after Deps.OnPurge.
	// Such rows need River, as DeleteUsers does.
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
	// email or phone verified on the account. It merges PublicMetadata's
	// top-level keys over the account's, keeps the earlier CreatedAt and the
	// later LastLogin, and fills a PreferredLanguage the account lacks. Only a
	// row bound by ID links Providers, and stores PasswordHash when the account
	// has no password: the row's own verified flags never do. It never changes
	// identity, contacts, verification, bans or deletion. A row that is not
	// bound is skipped with ImportUnboundMatch.
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

// ImportReason explains a skipped or rejected import row: one of the
// constants below, or the validation code of the rejected field (such as
// "invalid_email").
type ImportReason string

const (
	ImportAlreadyExists                ImportReason = "already_exists"
	ImportDuplicateInBatch             ImportReason = "duplicate_in_batch"
	ImportUnboundMatch                 ImportReason = "unbound_match"
	ImportDeleted                      ImportReason = "deleted"
	ImportIdentifierConflict           ImportReason = "identifier_conflict"
	ImportUsernameUnavailable          ImportReason = "username_unavailable"
	ImportProviderAlreadyLinked        ImportReason = "provider_already_linked"
	ImportProviderChangeRequiresUnlink ImportReason = "provider_change_requires_unlink"
	ImportInvalidID                    ImportReason = "invalid_id"
	ImportInvalidText                  ImportReason = "invalid_text"
	ImportInvalidPasswordHash          ImportReason = "invalid_password_hash"
	ImportInvalidBan                   ImportReason = "invalid_ban"
	ImportInvalidProvider              ImportReason = "invalid_provider"
	ImportInvalidDeletedAt             ImportReason = "invalid_deleted_at"
	// Solana link rows.
	ImportInvalidUserID           ImportReason = "invalid_user_id"
	ImportInvalidAddress          ImportReason = "invalid_address"
	ImportMissingSource           ImportReason = "missing_source"
	ImportMissingSourceID         ImportReason = "missing_source_id"
	ImportMissingUser             ImportReason = "missing_user"
	ImportAddressOwnedByOtherUser ImportReason = "address_owned_by_other_user"
	ImportAlreadyVerified         ImportReason = "already_verified"
	ImportAlreadyImported         ImportReason = "already_imported"
	ImportUserHasDifferentAddress ImportReason = "user_has_different_address"
	ImportProviderLinkConflict    ImportReason = "provider_link_conflict"
)

// ImportRow is one row's outcome. Every row but a rejected one has UserID;
// skipped and merged rows say which identifier found the account, and
// Reason explains skipped and rejected rows.
type ImportRow struct {
	Index     int          `json:"index"`
	UserID    string       `json:"user_id"`
	MatchedBy ImportMatch  `json:"matched_by"`
	Status    ImportStatus `json:"status"`
	Reason    ImportReason `json:"reason"`
}

// ImportResult reports every row, in input order.
type ImportResult struct {
	Rows     []ImportRow `json:"rows"`
	Inserted int         `json:"inserted"`
	Skipped  int         `json:"skipped"`
	Merged   int         `json:"merged"`
	Rejected int         `json:"rejected"`
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
	Index   int          `json:"index"`
	UserID  string       `json:"user_id"`
	Address string       `json:"address"`
	Status  ImportStatus `json:"status"`
	Reason  ImportReason `json:"reason"`
}

// ImportSolanaLinksResult reports every wallet row, in input order.
type ImportSolanaLinksResult struct {
	Rows     []ImportSolanaLinkRow `json:"rows"`
	Inserted int                   `json:"inserted"`
	Skipped  int                   `json:"skipped"`
	Rejected int                   `json:"rejected"`
}

// ProviderLink is an external identity to sign in with: the provider's issuer
// and subject, its configured name, and the email it reported.
type ProviderLink struct {
	Issuer   string
	Subject  string
	Provider string
	Email    string
}
