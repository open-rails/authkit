package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
)

// newAccount is one account row to create: a registration, an import row or a
// bootstrap user. normalizeImportUserInput validates it.
type newAccount struct {
	Email         string
	PhoneNumber   string
	Username      string
	EmailVerified bool
	PhoneVerified bool
	BannedAt      *time.Time
	BannedUntil   *time.Time
	BanReason     *string
	BannedBy      *string
	Metadata      map[string]any
	CreatedAt     *time.Time
	UpdatedAt     *time.Time
	PasswordHash  string
	HashAlgo      string
}

// importUsersChunkSize bounds rows per transaction.
const importUsersChunkSize = 1000

// importChunkAttempts bounds retries of a chunk that lost a provider link to
// a concurrent writer; each retry sees the winner and rejects that row.
const importChunkAttempts = 3

// importRejection rejects one import row with its reason.
type importRejection iam.ImportReason

func (r importRejection) Error() string { return string(r) }

var (
	errImportInvalidID           = importRejection(iam.ImportInvalidID)
	errImportInvalidText         = importRejection(iam.ImportInvalidText)
	errImportInvalidPasswordHash = importRejection(iam.ImportInvalidPasswordHash)
	errImportInvalidBan          = importRejection(iam.ImportInvalidBan)
	errImportInvalidProvider     = importRejection(iam.ImportInvalidProvider)
	errImportInvalidDeletedAt    = importRejection(iam.ImportInvalidDeletedAt)
	errImportProviderRaced       = errors.New("authkit: import lost a provider link to a concurrent writer")
)

// importRow is one validated ImportUsers row and, once its chunk commits, its
// outcome.
type importRow struct {
	idx       int
	id        string // declared, or generated for an insert
	declared  bool
	in        newAccount
	email     *string
	phone     *string
	username  string
	name      string // the username's claim key
	metadata  string
	createdAt time.Time
	updatedAt time.Time
	lastLogin *time.Time
	language  *string
	avatar    *string
	deletedAt *time.Time
	providers []iam.ProviderLink
	out       iam.ImportRow
}

type importKey struct {
	match iam.ImportMatch
	value string
}

// providerKey is an external identity: user_providers' (issuer, subject).
type providerKey struct{ issuer, subject string }

// keys lists the row's identifiers in match priority order.
func (p *importRow) keys() []importKey {
	var out []importKey
	if p.declared {
		out = append(out, importKey{iam.ImportMatchID, p.id})
	}
	if p.email != nil {
		out = append(out, importKey{iam.ImportMatchEmail, strings.ToLower(*p.email)})
	}
	if p.phone != nil {
		out = append(out, importKey{iam.ImportMatchPhone, *p.phone})
	}
	return append(out, importKey{iam.ImportMatchUsername, p.name})
}

func importRejected(idx int, reason iam.ImportReason) iam.ImportRow {
	return iam.ImportRow{Index: idx, Status: iam.ImportRejected, Reason: reason}
}

// ImportUsers bulk-imports accounts (target: 500k+ rows) as a host operation.
// Rows are validated in Go, then each chunk runs in one transaction: find the
// accounts its rows name, insert the rest with one multi-row INSERT, store
// their password hashes, and merge where asked. A row sharing an identifier
// with an earlier row of the batch is that row's account. A row whose
// identifiers name two accounts is rejected. Matching is never proof: only an
// id, or a contact verified on the account, binds a row for a merge.
func (s *Engine) ImportUsers(ctx context.Context, rows []iam.ImportUser, opts iam.ImportOptions, options ...ops.Option) (iam.ImportResult, error) {
	if err := noOptions("ImportUsers", options); err != nil {
		return iam.ImportResult{}, err
	}
	merge := false
	switch opts.OnConflict {
	case "", iam.ImportSkip:
	case iam.ImportMerge:
		merge = true
	default:
		return iam.ImportResult{}, fmt.Errorf("authkit: unknown import conflict mode %q", opts.OnConflict)
	}
	res := iam.ImportResult{Rows: make([]iam.ImportRow, len(rows))}
	if len(rows) == 0 {
		return res, nil
	}
	if err := s.requirePG(); err != nil {
		return iam.ImportResult{}, err
	}
	type duplicate struct {
		idx int
		of  *importRow
		by  iam.ImportMatch
	}
	var prepared []*importRow
	var dups []duplicate
	first := map[importKey]*importRow{}
	linked := map[providerKey]bool{}
	deletions := false
	for i, in := range rows {
		res.Rows[i].Index = i
		p, err := s.prepareImportRow(i, in)
		if err != nil {
			res.Rows[i] = importRejected(i, importRejectReason(err))
			continue
		}
		var of *importRow
		var by iam.ImportMatch
		conflict := false
		for _, k := range p.keys() {
			if f, ok := first[k]; ok {
				if of == nil {
					of, by = f, k.match
				} else if f != of {
					conflict = true
				}
			}
		}
		held := false
		for _, l := range p.providers {
			held = held || linked[providerKey{l.Issuer, l.Subject}]
		}
		switch {
		case conflict:
			res.Rows[i] = importRejected(i, iam.ImportIdentifierConflict)
		case of != nil:
			dups = append(dups, duplicate{i, of, by})
		case held:
			res.Rows[i] = importRejected(i, iam.ImportProviderAlreadyLinked)
		default:
			for _, k := range p.keys() {
				first[k] = p
			}
			for _, l := range p.providers {
				linked[providerKey{l.Issuer, l.Subject}] = true
			}
			deletions = deletions || p.deletedAt != nil
			prepared = append(prepared, p)
		}
	}
	// A deleted row starts the account lifecycle, which needs River.
	var client *river.Client[pgx.Tx]
	var err error
	if deletions {
		if client, err = s.deletionRiver(); err != nil {
			return iam.ImportResult{}, err
		}
	}
	for start := 0; start < len(prepared) && err == nil; start += importUsersChunkSize {
		chunk := prepared[start:min(start+importUsersChunkSize, len(prepared))]
		for attempt := 1; ; attempt++ {
			err = s.importChunk(ctx, chunk, merge, client)
			if !errors.Is(err, errImportProviderRaced) || attempt == importChunkAttempts {
				break
			}
		}
	}
	if err == nil {
		err = s.importBannedBy(ctx, prepared)
	}
	for _, p := range prepared {
		res.Rows[p.idx] = p.out
	}
	for _, d := range dups {
		switch {
		case d.of.out.Status == "":
		case d.of.out.UserID == "":
			res.Rows[d.idx] = importRejected(d.idx, iam.ImportDuplicateInBatch)
		default:
			res.Rows[d.idx] = iam.ImportRow{Index: d.idx, UserID: d.of.out.UserID, MatchedBy: d.by, Status: iam.ImportSkipped, Reason: iam.ImportDuplicateInBatch}
		}
	}
	for _, r := range res.Rows {
		switch r.Status {
		case iam.ImportInserted:
			res.Inserted++
		case iam.ImportSkipped:
			res.Skipped++
		case iam.ImportMerged:
			res.Merged++
		case iam.ImportRejected:
			res.Rejected++
		}
	}
	return res, err
}

func (s *Engine) prepareImportRow(idx int, in iam.ImportUser) (*importRow, error) {
	if !validImportText(in) {
		return nil, errImportInvalidText
	}
	acct := newAccount{
		Email: in.Email, PhoneNumber: in.Phone, Username: in.Username,
		EmailVerified: in.EmailVerified, PhoneVerified: in.PhoneVerified,
		Metadata: in.Metadata, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	}
	if b := in.Ban; b != nil {
		by := strings.TrimSpace(deref(b.By))
		if b.At.IsZero() || by != "" && !isUUID(by) {
			return nil, errImportInvalidBan
		}
		at := b.At
		acct.BannedAt, acct.BannedUntil, acct.BanReason = &at, b.Until, nullable(strings.TrimSpace(deref(b.Reason)))
		if by != "" {
			by = strings.ToLower(by)
			acct.BannedBy = &by
		}
	}
	if h := in.PasswordHash; h != nil {
		acct.PasswordHash, acct.HashAlgo = strings.TrimSpace(h.Hash), string(h.Algo)
		if acct.HashAlgo == "" || acct.PasswordHash == "" && h.Algo != iam.HashLegacyResetRequired ||
			validatePasswordHashForStorage(acct.PasswordHash, acct.HashAlgo) != nil {
			return nil, errImportInvalidPasswordHash
		}
	}
	email, phone, username, _, metadata, createdAt, updatedAt, err := s.normalizeImportUserInput(acct)
	if err != nil {
		return nil, err
	}
	p := &importRow{idx: idx, in: acct, email: email, phone: phone, username: username, name: strings.ToLower(username),
		metadata: metadata, createdAt: createdAt, updatedAt: updatedAt, lastLogin: utcTime(in.LastLogin)}
	language, err := authflow.NormalizePreferredLanguage(in.PreferredLanguage)
	if err != nil {
		return nil, err
	}
	p.language = nullable(language)
	if p.avatar, err = normalizeAvatarURL(in.AvatarURL); err != nil {
		return nil, err
	}
	if in.DeletedAt != nil {
		if in.DeletedAt.After(time.Now()) {
			return nil, errImportInvalidDeletedAt
		}
		p.deletedAt = utcTime(in.DeletedAt)
	}
	issuers := map[string]bool{}
	for _, l := range in.Providers {
		l.Issuer, l.Subject, l.Provider, l.Email = strings.TrimSpace(l.Issuer), strings.TrimSpace(l.Subject), strings.TrimSpace(l.Provider), strings.TrimSpace(l.Email)
		// user_providers holds one identity per account and issuer. Wallets
		// import only as ImportSolanaLinks reservations.
		if l.Issuer == "" || l.Subject == "" || issuers[l.Issuer] || l.Provider == solanaProviderSlug || strings.HasPrefix(l.Issuer, "solana:") {
			return nil, errImportInvalidProvider
		}
		issuers[l.Issuer] = true
		p.providers = append(p.providers, l)
	}
	if id := strings.TrimSpace(in.ID); id != "" {
		if !isUUID(id) {
			return nil, errImportInvalidID
		}
		p.id, p.declared = strings.ToLower(id), true
	} else if p.id, err = newUUIDV7String(); err != nil {
		return nil, err
	}
	return p, nil
}

// importChunk imports one chunk in one transaction. Outcomes stand only once
// it commits; on error every row of the chunk is left unreported.
func (s *Engine) importChunk(ctx context.Context, chunk []*importRow, merge bool, client *river.Client[pgx.Tx]) (err error) {
	defer func() {
		if err != nil {
			for _, p := range chunk {
				p.out = iam.ImportRow{Index: p.idx}
			}
		}
	}()
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.groupStoreFor(tx)
	q := db.New(tx)
	names := make([]string, len(chunk))
	for i, p := range chunk {
		names[i] = p.name
	}
	// Hold the names' claim locks so a matched-free name stays free until the
	// insert, and drop expired aliases so they neither match nor block.
	if err = lockNameClaims(ctx, tx, names...); err != nil {
		return err
	}
	if err = q.ImportReleaseAliases(ctx, db.ImportReleaseAliasesParams{Names: names, Now: s.namingNow()}); err != nil {
		return err
	}
	fresh, err := s.resolveImportRows(ctx, st, chunk, merge)
	if err != nil {
		return err
	}
	if fresh, err = rejectHeldProviders(ctx, q, fresh); err != nil {
		return err
	}
	inserted, err := insertImportRows(ctx, q, fresh)
	if err != nil {
		return err
	}
	var raced, passwords, providers []*importRow
	for _, p := range fresh {
		if !inserted[p.id] {
			raced = append(raced, p)
			continue
		}
		p.out = iam.ImportRow{Index: p.idx, UserID: p.id, Status: iam.ImportInserted}
		if p.in.HashAlgo != "" {
			passwords = append(passwords, p)
		}
		if len(p.providers) > 0 {
			providers = append(providers, p)
		}
	}
	if len(raced) > 0 {
		// A concurrent writer took an identifier after the match: match again.
		left, err := s.resolveImportRows(ctx, st, raced, merge)
		if err != nil {
			return err
		}
		for _, p := range left {
			p.out = importRejected(p.idx, iam.ImportIdentifierConflict)
		}
	}
	if err = insertImportPasswords(ctx, q, passwords); err != nil {
		return err
	}
	if err = insertImportProviders(ctx, q, providers); err != nil {
		return err
	}
	for _, p := range fresh {
		if inserted[p.id] && p.deletedAt != nil {
			// As the system's DeleteUsers would have: deleted_by stays NULL.
			if err = s.createAccountDeletion(ctx, tx, client, p.id, nil); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

type importHit struct {
	match    iam.ImportMatch
	userID   string
	deleted  bool
	verified bool // a contact hit verified on the account
	missing  bool // a username reserved for a purged account
}

// resolveImportRows finds the accounts rows name, records the outcome of every
// matched or conflicting row (merging where bound), and returns the rows that
// name no account.
func (s *Engine) resolveImportRows(ctx context.Context, st *permissionGroupStore, rows []*importRow, merge bool) ([]*importRow, error) {
	hits, err := s.importHits(ctx, db.New(st.q), rows)
	if err != nil {
		return nil, err
	}
	var fresh []*importRow
	for _, p := range rows {
		var found []importHit
		for _, k := range p.keys() {
			if h, ok := hits[k]; ok {
				found = append(found, h)
			}
		}
		if len(found) == 0 {
			fresh = append(fresh, p)
			continue
		}
		top := found[0]
		conflict := p.declared && top.match != iam.ImportMatchID
		// credentialBound: bound strongly enough to add a password or providers.
		bound, credentialBound := false, false
		for _, h := range found {
			conflict = conflict || h.userID != top.userID
			switch {
			case h.match == iam.ImportMatchID:
				bound, credentialBound = true, true
			case h.verified:
				bound = true
				credentialBound = credentialBound || h.match == iam.ImportMatchEmail && p.in.EmailVerified || h.match == iam.ImportMatchPhone && p.in.PhoneVerified
			}
		}
		skipped := iam.ImportRow{Index: p.idx, UserID: top.userID, MatchedBy: top.match, Status: iam.ImportSkipped, Reason: iam.ImportAlreadyExists}
		switch {
		case top.missing:
			p.out = importRejected(p.idx, iam.ImportUsernameUnavailable)
		case conflict:
			p.out = importRejected(p.idx, iam.ImportIdentifierConflict)
		case top.deleted:
			skipped.Reason = iam.ImportDeleted
			p.out = skipped
		case !merge:
			p.out = skipped
		case !bound:
			skipped.Reason = iam.ImportUnboundMatch
			p.out = skipped
		default:
			err := st.savepoint(ctx, func() error { return s.mergeImportRow(ctx, st, p, top.userID, credentialBound) })
			if err != nil {
				if code := errmodel.CodeOf(err); code == "" || code == errmodel.CodeInternalError {
					return nil, err
				}
				p.out = importRejected(p.idx, importRejectReason(err))
				continue
			}
			p.out = iam.ImportRow{Index: p.idx, UserID: top.userID, MatchedBy: top.match, Status: iam.ImportMerged}
		}
	}
	return fresh, nil
}

// importHits reads, in four queries, every account the rows' identifiers
// name: by id, email, phone, and canonical name or live alias.
func (s *Engine) importHits(ctx context.Context, q *db.Queries, rows []*importRow) (map[importKey]importHit, error) {
	var ids, emails, phones, names []string
	for _, p := range rows {
		if p.declared {
			ids = append(ids, p.id)
		}
		if p.email != nil {
			emails = append(emails, strings.ToLower(*p.email))
		}
		if p.phone != nil {
			phones = append(phones, *p.phone)
		}
		names = append(names, p.name)
	}
	// The four ImportHitsBy* rows share one shape.
	out := map[importKey]importHit{}
	add := func(match iam.ImportMatch, r db.ImportHitsByIDRow) {
		out[importKey{match, r.Key}] = importHit{match: match, userID: r.UserID, deleted: r.Deleted, verified: r.Verified, missing: r.Missing}
	}
	if len(ids) > 0 {
		hits, err := q.ImportHitsByID(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, r := range hits {
			add(iam.ImportMatchID, r)
		}
	}
	if len(emails) > 0 {
		hits, err := q.ImportHitsByEmail(ctx, emails)
		if err != nil {
			return nil, err
		}
		for _, r := range hits {
			add(iam.ImportMatchEmail, db.ImportHitsByIDRow(r))
		}
	}
	if len(phones) > 0 {
		hits, err := q.ImportHitsByPhone(ctx, phones)
		if err != nil {
			return nil, err
		}
		for _, r := range hits {
			add(iam.ImportMatchPhone, db.ImportHitsByIDRow(r))
		}
	}
	hits, err := q.ImportHitsByName(ctx, db.ImportHitsByNameParams{Names: names, Now: s.namingNow()})
	if err != nil {
		return nil, err
	}
	for _, r := range hits {
		add(iam.ImportMatchUsername, db.ImportHitsByIDRow(r))
	}
	return out, nil
}

// mergeImportRow merges a bound row into its account: metadata, the earlier
// creation time, the later last login, a language and avatar the account
// lacks and, when withCredentials, the row's providers and a password the
// account lacks. Identity, contacts, verification, bans and deletion stay as
// they are.
func (s *Engine) mergeImportRow(ctx context.Context, st *permissionGroupStore, p *importRow, userID string, withCredentials bool) error {
	q := db.New(st.q)
	if err := q.ImportMergeUser(ctx, db.ImportMergeUserParams{
		ID: userID, Metadata: []byte(p.metadata), CreatedAt: p.createdAt, LastLogin: p.lastLogin,
		PreferredLanguage: p.language, AvatarURL: p.avatar,
	}); err != nil {
		return err
	}
	if !withCredentials {
		return nil
	}
	for _, l := range p.providers {
		if _, err := linkProviderByIssuer(ctx, q, userID, l.Issuer, l.Provider, l.Subject, nullable(l.Email)); err != nil {
			return err
		}
	}
	if p.in.HashAlgo == "" {
		return nil
	}
	return q.ImportMergePassword(ctx, db.ImportMergePasswordParams{UserID: userID, PasswordHash: p.in.PasswordHash, HashAlgo: p.in.HashAlgo})
}

// importUserColumns is one users row for ImportInsertUsers, keyed by column.
type importUserColumns struct {
	ID                string          `json:"id"`
	Email             *string         `json:"email"`
	PhoneNumber       *string         `json:"phone_number"`
	Username          string          `json:"username"`
	EmailVerified     bool            `json:"email_verified"`
	PhoneVerified     bool            `json:"phone_verified"`
	BannedAt          *time.Time      `json:"banned_at"`
	BannedUntil       *time.Time      `json:"banned_until"`
	BanReason         *string         `json:"ban_reason"`
	Metadata          json.RawMessage `json:"metadata"`
	CreatedAt         *time.Time      `json:"created_at"`
	UpdatedAt         *time.Time      `json:"updated_at"`
	LastLogin         *time.Time      `json:"last_login"`
	PreferredLanguage *string         `json:"preferred_language"`
	AvatarURL         *string         `json:"avatar_url"`
	DeletedAt         *time.Time      `json:"deleted_at"`
}

// importBannedBy records who banned the inserted rows, once every chunk has
// committed, so a banner imported later in the batch counts too.
func (s *Engine) importBannedBy(ctx context.Context, rows []*importRow) error {
	var arg db.ImportSetBannedByParams
	for _, p := range rows {
		if p.out.Status == iam.ImportInserted && p.in.BannedBy != nil {
			arg.UserIds, arg.BannedBy = append(arg.UserIds, p.id), append(arg.BannedBy, *p.in.BannedBy)
		}
	}
	if len(arg.UserIds) == 0 {
		return nil
	}
	return s.q.ImportSetBannedBy(ctx, arg)
}

// insertImportRows inserts rows in one statement and returns the ids that
// landed; a row losing a uniqueness race to another writer does not.
func insertImportRows(ctx context.Context, q *db.Queries, rows []*importRow) (map[string]bool, error) {
	inserted := map[string]bool{}
	if len(rows) == 0 {
		return inserted, nil
	}
	cols := make([]importUserColumns, len(rows))
	for i, r := range rows {
		cols[i] = importUserColumns{
			ID: r.id, Email: r.email, PhoneNumber: r.phone, Username: r.username,
			EmailVerified: r.in.EmailVerified, PhoneVerified: r.in.PhoneVerified,
			BannedAt: pgTime(r.in.BannedAt), BannedUntil: pgTime(r.in.BannedUntil), BanReason: r.in.BanReason,
			Metadata: json.RawMessage(r.metadata), CreatedAt: pgTime(&r.createdAt), UpdatedAt: pgTime(&r.updatedAt),
			LastLogin: pgTime(r.lastLogin), PreferredLanguage: r.language, AvatarURL: r.avatar, DeletedAt: pgTime(r.deletedAt),
		}
	}
	users, err := json.Marshal(cols)
	if err != nil {
		return nil, err
	}
	ids, err := q.ImportInsertUsers(ctx, users)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		inserted[id] = true
	}
	return inserted, nil
}

// insertImportPasswords stores the validated hashes of freshly inserted rows.
func insertImportPasswords(ctx context.Context, q *db.Queries, rows []*importRow) error {
	if len(rows) == 0 {
		return nil
	}
	var arg db.ImportInsertPasswordsParams
	for _, r := range rows {
		arg.UserIds = append(arg.UserIds, r.id)
		arg.PasswordHashes = append(arg.PasswordHashes, r.in.PasswordHash)
		arg.HashAlgos = append(arg.HashAlgos, r.in.HashAlgo)
	}
	return q.ImportInsertPasswords(ctx, arg)
}

// rejectHeldProviders rejects the rows naming an identity some account holds,
// verified or not, and returns the rest.
func rejectHeldProviders(ctx context.Context, q *db.Queries, rows []*importRow) ([]*importRow, error) {
	var arg db.ImportHeldProvidersParams
	for _, p := range rows {
		for _, l := range p.providers {
			arg.Issuers, arg.Subjects = append(arg.Issuers, l.Issuer), append(arg.Subjects, l.Subject)
		}
	}
	if len(arg.Issuers) == 0 {
		return rows, nil
	}
	found, err := q.ImportHeldProviders(ctx, arg)
	if err != nil {
		return nil, err
	}
	held := map[providerKey]bool{}
	for _, k := range found {
		held[providerKey{k.Issuer, k.Subject}] = true
	}
	var out []*importRow
	for _, p := range rows {
		ok := true
		for _, l := range p.providers {
			ok = ok && !held[providerKey{l.Issuer, l.Subject}]
		}
		if ok {
			out = append(out, p)
		} else {
			p.out = importRejected(p.idx, iam.ImportProviderAlreadyLinked)
		}
	}
	return out, nil
}

// insertImportProviders links the providers of freshly inserted rows. An
// identity a concurrent writer took since rejectHeldProviders fails the chunk
// with errImportProviderRaced, to be retried.
func insertImportProviders(ctx context.Context, q *db.Queries, rows []*importRow) error {
	var arg db.ImportInsertProvidersParams
	for _, p := range rows {
		for _, l := range p.providers {
			arg.UserIds, arg.Issuers, arg.Subjects = append(arg.UserIds, p.id), append(arg.Issuers, l.Issuer), append(arg.Subjects, l.Subject)
			arg.ProviderSlugs, arg.EmailsAtProvider = append(arg.ProviderSlugs, l.Provider), append(arg.EmailsAtProvider, l.Email)
		}
	}
	if len(arg.UserIds) == 0 {
		return nil
	}
	n, err := q.ImportInsertProviders(ctx, arg)
	if err != nil {
		return err
	}
	if n != int64(len(arg.UserIds)) {
		return errImportProviderRaced
	}
	return nil
}

func utcTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// pgTime is t as a timestamptz parameter stores it: UTC, truncated to the
// microsecond, so its JSON text converts exactly.
func pgTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC().Truncate(time.Microsecond)
	return &u
}

// importRejectReason is a row's reject reason: its import rejection or
// validation code, else the error text.
func importRejectReason(err error) iam.ImportReason {
	var r importRejection
	if errors.As(err, &r) {
		return iam.ImportReason(r)
	}
	if code := errmodel.CodeOf(err); code != "" {
		return iam.ImportReason(code)
	}
	return iam.ImportReason(err.Error())
}

// validImportText reports whether every text field of in, metadata included,
// is valid UTF-8. The JSON bulk insert would store invalid bytes as U+FFFD.
func validImportText(in iam.ImportUser) bool {
	texts := []string{in.ID, in.Email, in.Phone, in.Username, in.PreferredLanguage, in.AvatarURL}
	if in.PasswordHash != nil {
		texts = append(texts, in.PasswordHash.Hash, string(in.PasswordHash.Algo))
	}
	if in.Ban != nil {
		texts = append(texts, deref(in.Ban.Reason), deref(in.Ban.By))
	}
	for _, l := range in.Providers {
		texts = append(texts, l.Issuer, l.Subject, l.Provider, l.Email)
	}
	for _, t := range texts {
		if !utf8.ValidString(t) {
			return false
		}
	}
	return validUTF8Value(in.Metadata)
}

// validUTF8Value reports whether every string in v, a JSON-shaped value,
// and every map key is valid UTF-8.
func validUTF8Value(v any) bool {
	switch v := v.(type) {
	case string:
		return utf8.ValidString(v)
	case map[string]any:
		for k, e := range v {
			if !utf8.ValidString(k) || !validUTF8Value(e) {
				return false
			}
		}
	case []any:
		for _, e := range v {
			if !validUTF8Value(e) {
				return false
			}
		}
	}
	return true
}
