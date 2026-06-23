package authcore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// ImportUserStatus is the per-row outcome of ImportUsers.
type ImportUserStatus string

const (
	// ImportStatusInserted: the user row was created.
	ImportStatusInserted ImportUserStatus = "inserted"
	// ImportStatusSkipped: a matching user already existed (by username/email/
	// phone), or the row duplicated an earlier row in the same batch. Skipped
	// rows are left untouched — bulk import is insert-or-skip, never overwrite,
	// so a re-run is idempotent and never clobbers data a user changed after
	// import.
	ImportStatusSkipped ImportUserStatus = "skipped"
	// ImportStatusRejected: the row failed validation/normalization (bad email,
	// username, phone) and was not imported.
	ImportStatusRejected ImportUserStatus = "rejected"
)

// ImportUserResult is the outcome for one input row, addressed by its original
// index in the input slice.
type ImportUserResult struct {
	Index  int
	UserID string // set when Status == inserted
	Status ImportUserStatus
	Reason string // set for skipped/rejected (machine-ish: "duplicate_in_batch", "already_exists", or a validation code)
}

// ImportUsersResult aggregates the per-row outcomes plus rollup counts.
type ImportUsersResult struct {
	Results  []ImportUserResult
	Inserted int
	Skipped  int
	Rejected int
}

// importUsersChunkSize bounds rows per multi-row INSERT. 13 cols/row keeps the
// bound query well under PostgreSQL's 65535-parameter ceiling.
const importUsersChunkSize = 1000

type preparedImportRow struct {
	idx       int
	id        string
	email     *string
	phone     *string
	username  string
	in        ImportUserInput
	metadata  string
	bannedBy  *string
	createdAt time.Time
	updatedAt time.Time
}

// ImportUsers bulk-imports users for fast legacy migration (target: 500k+). It is
// the sole import API: validate/normalize happens in Go (identical to the legacy
// single-row path) so accuracy is preserved, then clean rows load via chunked
// multi-row INSERTs — no per-row round-trips.
//
// Semantics are INSERT-OR-SKIP (not upsert): a row whose username/email/phone
// already exists, or which duplicates an earlier row in the same batch, is
// skipped and reported, never overwritten. This makes a re-run idempotent (resume
// a partial import) without clobbering changes a user made after they were
// imported. Invalid rows are rejected individually and never abort the batch.
//
// Each input may carry an optional pre-hashed PasswordHash; for inserted rows it
// is stored verbatim (the verify-time hash whitelist still governs login).
func (s *Service) ImportUsers(ctx context.Context, inputs []ImportUserInput) (ImportUsersResult, error) {
	res := ImportUsersResult{Results: make([]ImportUserResult, len(inputs))}
	if len(inputs) == 0 {
		return res, nil
	}
	if err := s.requirePG(); err != nil {
		return res, err
	}

	// 1. Validate/normalize + in-batch dedup.
	prepared := make([]preparedImportRow, 0, len(inputs))
	seenUser := make(map[string]struct{}, len(inputs))
	seenEmail := make(map[string]struct{}, len(inputs))
	seenPhone := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := normalizeImportUserInput(in)
		if err != nil {
			res.Results[i] = ImportUserResult{Index: i, Status: ImportStatusRejected, Reason: importRejectReason(err)}
			res.Rejected++
			continue
		}
		if _, dup := seenUser[username]; dup {
			res.Results[i] = ImportUserResult{Index: i, Status: ImportStatusSkipped, Reason: "duplicate_in_batch"}
			res.Skipped++
			continue
		}
		if email != nil {
			if _, dup := seenEmail[*email]; dup {
				res.Results[i] = ImportUserResult{Index: i, Status: ImportStatusSkipped, Reason: "duplicate_in_batch"}
				res.Skipped++
				continue
			}
		}
		if phone != nil {
			if _, dup := seenPhone[*phone]; dup {
				res.Results[i] = ImportUserResult{Index: i, Status: ImportStatusSkipped, Reason: "duplicate_in_batch"}
				res.Skipped++
				continue
			}
		}
		seenUser[username] = struct{}{}
		if email != nil {
			seenEmail[*email] = struct{}{}
		}
		if phone != nil {
			seenPhone[*phone] = struct{}{}
		}
		id, err := newUUIDV7String()
		if err != nil {
			return res, err
		}
		prepared = append(prepared, preparedImportRow{
			idx: i, id: id, email: email, phone: phone, username: username,
			in: in, metadata: metadata, bannedBy: bannedBy, createdAt: createdAt, updatedAt: updatedAt,
		})
	}
	if len(prepared) == 0 {
		return res, nil
	}

	// 2. Bulk INSERT in chunks. ON CONFLICT DO NOTHING makes a row that already
	//    exists (ANY unique constraint: username/email/phone) a silent skip rather
	//    than an error, so a re-run is idempotent and one collision never aborts a
	//    chunk. RETURNING id reconciles which rows actually landed; the rest were
	//    already in the DB. No separate existence pre-check — at 500k that would
	//    mean a giant ANY($1) array for no extra correctness.
	for start := 0; start < len(prepared); start += importUsersChunkSize {
		end := start + importUsersChunkSize
		if end > len(prepared) {
			end = len(prepared)
		}
		chunk := prepared[start:end]
		insertedIDs, err := s.bulkInsertUsers(ctx, chunk)
		if err != nil {
			return res, err
		}
		var pwRows []preparedImportRow
		for _, p := range chunk {
			if _, ok := insertedIDs[p.id]; ok {
				res.Results[p.idx] = ImportUserResult{Index: p.idx, UserID: p.id, Status: ImportStatusInserted}
				res.Inserted++
				if strings.TrimSpace(p.in.PasswordHash) != "" {
					pwRows = append(pwRows, p)
				}
			} else {
				res.Results[p.idx] = ImportUserResult{Index: p.idx, Status: ImportStatusSkipped, Reason: "already_exists"}
				res.Skipped++
			}
		}
		if len(pwRows) > 0 {
			if err := s.bulkInsertPasswordHashes(ctx, pwRows); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// bulkInsertUsers inserts a chunk via one multi-row INSERT and returns the set of
// ids that actually landed (ON CONFLICT DO NOTHING drops racing duplicates).
func (s *Service) bulkInsertUsers(ctx context.Context, chunk []preparedImportRow) (map[string]struct{}, error) {
	var b strings.Builder
	b.WriteString("INSERT INTO profiles.users (id, email, phone_number, username, email_verified, phone_verified, banned_at, banned_until, ban_reason, banned_by, metadata, created_at, updated_at) VALUES ")
	args := make([]any, 0, len(chunk)*13)
	for i, r := range chunk {
		if i > 0 {
			b.WriteString(",")
		}
		n := i * 13
		fmt.Fprintf(&b, "($%d::uuid,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d::uuid,$%d::jsonb,$%d,$%d)",
			n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10, n+11, n+12, n+13)
		args = append(args,
			r.id, r.email, r.phone, r.username, r.in.EmailVerified, r.in.PhoneVerified,
			r.in.BannedAt, r.in.BannedUntil, r.in.BanReason, r.bannedBy, r.metadata, r.createdAt, r.updatedAt)
	}
	b.WriteString(" ON CONFLICT DO NOTHING RETURNING id")
	rows, err := s.pg.Query(ctx, db.RewriteSQL(b.String(), s.dbSchema()), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inserted := make(map[string]struct{}, len(chunk))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		inserted[id] = struct{}{}
	}
	return inserted, rows.Err()
}

// bulkInsertPasswordHashes stores pre-hashed credentials for freshly-inserted
// users in one multi-row INSERT. ON CONFLICT (user_id) DO NOTHING since the user
// was just created.
func (s *Service) bulkInsertPasswordHashes(ctx context.Context, rows []preparedImportRow) error {
	var b strings.Builder
	b.WriteString("INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo, hash_params) VALUES ")
	args := make([]any, 0, len(rows)*4)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		n := i * 4
		fmt.Fprintf(&b, "($%d::uuid,$%d,$%d,$%d)", n+1, n+2, n+3, n+4)
		args = append(args, r.id, r.in.PasswordHash, r.in.HashAlgo, r.in.HashParams)
	}
	b.WriteString(" ON CONFLICT (user_id) DO NOTHING")
	_, err := s.pg.Exec(ctx, db.RewriteSQL(b.String(), s.dbSchema()), args...)
	return err
}

// importRejectReason maps a validation error to a stable-ish reason string for
// ImportUserResult. Falls back to the error text.
func importRejectReason(err error) string {
	if code := ValidationErrorCode(err); code != "" {
		return code
	}
	return err.Error()
}
