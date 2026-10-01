package authkit

import (
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ops"
)

// Option adjusts one operation. Every mutation and host operation takes
// ...Option; an operation refuses an option it does not take, never ignoring
// it.
type Option = ops.Option

// InTx runs the operation inside tx, the host's own transaction, so AuthKit's
// changes commit or roll back with the host's: a group and the app row that
// stores its ID, or neither. tx must be a READ COMMITTED transaction on the
// database of Deps.Postgres; AuthKit's schema needs no search_path entry.
// AuthKit works in a savepoint of tx: a refused operation rolls back to it and
// leaves tx usable. Its authority lock, the credential sweep and its event
// records are all part of tx, and the lock is held until tx ends, so commit
// promptly.
//
// CreateGroup, DeleteGroup, PurgeGroup, SetGroupRole, RemoveGroupMember,
// EnsureUserRole, CreateUser, PatchPublicMetadata, Unban, CreateAPIKey,
// RevokeAPIKey, CreateInvitation (a link), RevokeInvitation,
// UpsertRemoteApplication and DeleteRemoteApplication take it.
func InTx(tx pgx.Tx) Option { return ops.InTx(tx) }

// IfRole makes RemoveGroupMember remove the subject only while it holds
// role: a guard against a concurrent re-role.
func IfRole(role iam.Role) Option { return ops.IfRole(role) }

// IncludeDeleted makes User return a soft-deleted account too.
func IncludeDeleted() Option { return ops.IncludeDeleted() }
