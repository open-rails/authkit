package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
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

// importUsersChunkSize bounds rows per transaction and multi-row INSERT
// (16 parameters a row, far under PostgreSQL's 65535).
const importUsersChunkSize = 1000

// importChunkAttempts bounds retries of a chunk that lost a provider link to
// a concurrent writer; each retry sees the winner and rejects that row.
const importChunkAttempts = 3

var (
	errImportInvalidID           = errors.New("invalid_id")
	errImportInvalidPasswordHash = errors.New("invalid_password_hash")
	errImportInvalidProvider     = errors.New("invalid_provider")
	errImportInvalidDeletedAt    = errors.New("invalid_deleted_at")
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

func importRejected(idx int, reason string) iam.ImportRow {
	return iam.ImportRow{Index: idx, Status: iam.ImportRejected, Reason: reason}
}

// ImportUsers bulk-imports accounts (target: 500k+ rows) as a host operation.
// Rows are validated in Go, then each chunk runs in one transaction: find the
// accounts its rows name, insert the rest with one multi-row INSERT, store
// their password hashes, and merge where asked. A row sharing an identifier
// with an earlier row of the batch is that row's account. A row whose
// identifiers name two accounts is rejected. Matching is never proof: only an
// id, or a contact verified on the account, binds a row for a merge.
func (s *Engine) ImportUsers(ctx context.Context, rows []iam.ImportUser, opts iam.ImportOptions) (iam.ImportResult, error) {
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
			res.Rows[i] = importRejected(i, "identifier_conflict")
		case of != nil:
			dups = append(dups, duplicate{i, of, by})
		case held:
			res.Rows[i] = importRejected(i, errmodel.CodeProviderAlreadyLinked.String())
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
	for _, p := range prepared {
		res.Rows[p.idx] = p.out
	}
	for _, d := range dups {
		switch {
		case d.of.out.Status == "":
		case d.of.out.UserID == "":
			res.Rows[d.idx] = importRejected(d.idx, "duplicate_in_batch")
		default:
			res.Rows[d.idx] = iam.ImportRow{Index: d.idx, UserID: d.of.out.UserID, MatchedBy: d.by, Status: iam.ImportSkipped, Reason: "duplicate_in_batch"}
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
	acct := newAccount{
		Email: in.Email, PhoneNumber: in.Phone, Username: in.Username,
		EmailVerified: in.EmailVerified, PhoneVerified: in.PhoneVerified,
		BannedAt: in.BannedAt, BannedUntil: in.BannedUntil, BanReason: nullable(strings.TrimSpace(in.BanReason)),
		Metadata: in.Metadata, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
		PasswordHash: strings.TrimSpace(in.PasswordHash), HashAlgo: strings.TrimSpace(in.HashAlgo),
	}
	if acct.PasswordHash != "" || acct.HashAlgo != "" {
		if acct.HashAlgo == "" || acct.PasswordHash == "" && acct.HashAlgo != iam.HashAlgoLegacyResetRequired ||
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
	if merge {
		// A merged `reserved` flag is an owner-loss decision.
		if err = s.lockAuthority(ctx, tx); err != nil {
			return err
		}
	}
	st := s.groupStoreFor(tx)
	names := make([]string, len(chunk))
	for i, p := range chunk {
		names[i] = p.name
	}
	// Hold the names' claim locks so a matched-free name stays free until the
	// insert, and drop expired aliases so they neither match nor block.
	if err = lockNameClaims(ctx, tx, names...); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM name_claims WHERE owner_kind='user' AND persona='' AND name=ANY($1::text[]) AND NOT canonical AND expires_at<=$2`, names, s.namingNow()); err != nil {
		return err
	}
	fresh, err := s.resolveImportRows(ctx, st, chunk, merge)
	if err != nil {
		return err
	}
	if fresh, err = rejectHeldProviders(ctx, tx, fresh); err != nil {
		return err
	}
	inserted, err := insertImportRows(ctx, tx, fresh)
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
			p.out = importRejected(p.idx, "identifier_conflict")
		}
	}
	if err = insertImportPasswords(ctx, tx, passwords); err != nil {
		return err
	}
	if err = insertImportProviders(ctx, tx, providers); err != nil {
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
	hits, err := s.importHits(ctx, st.q, rows)
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
		skipped := iam.ImportRow{Index: p.idx, UserID: top.userID, MatchedBy: top.match, Status: iam.ImportSkipped, Reason: "already_exists"}
		switch {
		case top.missing:
			p.out = importRejected(p.idx, "username_unavailable")
		case conflict:
			p.out = importRejected(p.idx, "identifier_conflict")
		case top.deleted:
			skipped.Reason = "deleted"
			p.out = skipped
		case !merge:
			p.out = skipped
		case !bound:
			skipped.Reason = "unbound_match"
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
func (s *Engine) importHits(ctx context.Context, q db.DBTX, rows []*importRow) (map[importKey]importHit, error) {
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
	out := map[importKey]importHit{}
	read := func(match iam.ImportMatch, sql string, args ...any) error {
		r, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var key string
			h := importHit{match: match}
			if err := r.Scan(&key, &h.userID, &h.deleted, &h.verified, &h.missing); err != nil {
				return err
			}
			out[importKey{match, key}] = h
		}
		return r.Err()
	}
	if len(ids) > 0 {
		if err := read(iam.ImportMatchID, `SELECT id::text, id::text, deleted_at IS NOT NULL, true, false FROM users WHERE id=ANY($1::uuid[])`, ids); err != nil {
			return nil, err
		}
	}
	if len(emails) > 0 {
		if err := read(iam.ImportMatchEmail, `SELECT lower(email::text), id::text, deleted_at IS NOT NULL, email_verified, false FROM users WHERE email=ANY($1::text[]::public.citext[])`, emails); err != nil {
			return nil, err
		}
	}
	if len(phones) > 0 {
		if err := read(iam.ImportMatchPhone, `SELECT phone_number, id::text, deleted_at IS NOT NULL, phone_verified, false FROM users WHERE phone_number=ANY($1::text[])`, phones); err != nil {
			return nil, err
		}
	}
	err := read(iam.ImportMatchUsername, `SELECT c.name, c.owner_id::text, COALESCE(u.deleted_at IS NOT NULL, false), false, u.id IS NULL
 FROM name_claims c LEFT JOIN users u ON u.id=c.owner_id
 WHERE c.owner_kind='user' AND c.persona='' AND c.name=ANY($1::text[]) AND (c.canonical OR c.expires_at IS NULL OR c.expires_at>$2)`, names, s.namingNow())
	return out, err
}

// mergeImportRow merges a bound row into its account: metadata, the earlier
// creation time, the later last login, a language and avatar the account
// lacks and, when withCredentials, the row's providers and a password the
// account lacks. Identity, contacts, verification, bans and deletion stay as
// they are.
func (s *Engine) mergeImportRow(ctx context.Context, st *permissionGroupStore, p *importRow, userID string, withCredentials bool) error {
	if metadataMarksReserved([]byte(p.metadata)) {
		if err := s.refuseSubjectOwnerLoss(ctx, st, iam.UserSubject(userID)); err != nil {
			return err
		}
	}
	if _, err := st.q.Exec(ctx, `UPDATE users SET metadata=COALESCE(metadata,'{}'::jsonb) || $2::jsonb, created_at=LEAST(created_at,$3),
 last_login=GREATEST(last_login,$4), preferred_language=COALESCE(preferred_language,$5), avatar_url=COALESCE(avatar_url,$6), updated_at=now() WHERE id=$1::uuid`,
		userID, p.metadata, p.createdAt, p.lastLogin, p.language, p.avatar); err != nil {
		return err
	}
	if !withCredentials {
		return nil
	}
	for _, l := range p.providers {
		if _, err := linkProviderByIssuer(ctx, db.New(st.q), userID, l.Issuer, l.Provider, l.Subject, nullable(l.Email)); err != nil {
			return err
		}
	}
	if p.in.HashAlgo == "" {
		return nil
	}
	_, err := st.q.Exec(ctx, `INSERT INTO user_passwords (user_id, password_hash, hash_algo) VALUES ($1::uuid,$2,$3) ON CONFLICT (user_id) DO NOTHING`, userID, p.in.PasswordHash, p.in.HashAlgo)
	return err
}

// insertImportRows inserts rows with one multi-row INSERT and returns the ids
// that landed; a row losing a uniqueness race to another writer does not.
func insertImportRows(ctx context.Context, q pgx.Tx, rows []*importRow) (map[string]bool, error) {
	inserted := map[string]bool{}
	if len(rows) == 0 {
		return inserted, nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO users (id, email, phone_number, username, email_verified, phone_verified, banned_at, banned_until, ban_reason, metadata, created_at, updated_at, last_login, preferred_language, avatar_url, deleted_at) VALUES ")
	args := make([]any, 0, len(rows)*16)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		n := i * 16
		fmt.Fprintf(&b, "($%d::uuid,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d::jsonb,$%d,$%d,$%d,$%d,$%d,$%d)",
			n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10, n+11, n+12, n+13, n+14, n+15, n+16)
		args = append(args, r.id, r.email, r.phone, r.username, r.in.EmailVerified, r.in.PhoneVerified,
			r.in.BannedAt, r.in.BannedUntil, r.in.BanReason, r.metadata, r.createdAt, r.updatedAt,
			r.lastLogin, r.language, r.avatar, r.deletedAt)
	}
	b.WriteString(" ON CONFLICT DO NOTHING RETURNING id::text")
	res, err := q.Query(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	for res.Next() {
		var id string
		if err := res.Scan(&id); err != nil {
			return nil, err
		}
		inserted[id] = true
	}
	return inserted, res.Err()
}

// insertImportPasswords stores the validated hashes of freshly inserted rows.
func insertImportPasswords(ctx context.Context, q pgx.Tx, rows []*importRow) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO user_passwords (user_id, password_hash, hash_algo) VALUES ")
	args := make([]any, 0, len(rows)*3)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "($%d::uuid,$%d,$%d)", i*3+1, i*3+2, i*3+3)
		args = append(args, r.id, r.in.PasswordHash, r.in.HashAlgo)
	}
	b.WriteString(" ON CONFLICT (user_id) DO NOTHING")
	_, err := q.Exec(ctx, b.String(), args...)
	return err
}

// rejectHeldProviders rejects the rows naming an identity some account holds,
// verified or not, and returns the rest.
func rejectHeldProviders(ctx context.Context, tx pgx.Tx, rows []*importRow) ([]*importRow, error) {
	var issuers, subjects []string
	for _, p := range rows {
		for _, l := range p.providers {
			issuers, subjects = append(issuers, l.Issuer), append(subjects, l.Subject)
		}
	}
	if len(issuers) == 0 {
		return rows, nil
	}
	res, err := tx.Query(ctx, `SELECT p.issuer, p.subject FROM user_providers p
 JOIN unnest($1::text[], $2::text[]) AS k(issuer, subject) ON p.issuer=k.issuer AND p.subject=k.subject`, issuers, subjects)
	if err != nil {
		return nil, err
	}
	held := map[providerKey]bool{}
	for res.Next() {
		var k providerKey
		if err := res.Scan(&k.issuer, &k.subject); err != nil {
			res.Close()
			return nil, err
		}
		held[k] = true
	}
	res.Close()
	if err := res.Err(); err != nil {
		return nil, err
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
			p.out = importRejected(p.idx, errmodel.CodeProviderAlreadyLinked.String())
		}
	}
	return out, nil
}

// insertImportProviders links the providers of freshly inserted rows. An
// identity a concurrent writer took since rejectHeldProviders fails the chunk
// with errImportProviderRaced, to be retried.
func insertImportProviders(ctx context.Context, tx pgx.Tx, rows []*importRow) error {
	var users, issuers, subjects []string
	var slugs, emails []*string
	for _, p := range rows {
		for _, l := range p.providers {
			users, issuers, subjects = append(users, p.id), append(issuers, l.Issuer), append(subjects, l.Subject)
			slugs, emails = append(slugs, nullable(l.Provider)), append(emails, nullable(l.Email))
		}
	}
	if len(users) == 0 {
		return nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO user_providers (user_id, issuer, provider_slug, subject, email_at_provider)
 SELECT * FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[]) ON CONFLICT DO NOTHING`, users, issuers, slugs, subjects, emails)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(users)) {
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

// importRejectReason is a row's reject reason: its validation code, or the
// error text.
func importRejectReason(err error) string {
	if code := errmodel.CodeOf(err); code != "" {
		return string(code)
	}
	return err.Error()
}
