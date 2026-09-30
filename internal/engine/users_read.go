package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
)

// Account reads. They take no actor: the host is the trust boundary, and
// httpapi gates its read routes with root:users:read.

// User returns one account. Soft-deleted accounts are excluded unless opts
// include ops.IncludeDeleted(); a miss is iam.ErrUserNotFound.
func (s *Engine) User(ctx context.Context, ref iam.UserRef, opts ...ops.Option) (iam.User, error) {
	o, err := ops.Resolve("User", opts, ops.KindIncludeDeleted)
	if err != nil {
		return iam.User{}, err
	}
	if err := s.requirePG(); err != nil {
		return iam.User{}, err
	}
	value := ref.Value()
	if value == "" {
		return iam.User{}, iam.ErrUserNotFound
	}
	var r db.User
	switch ref.Key() {
	case iam.UserKeyID:
		if !isUUID(value) {
			return iam.User{}, iam.ErrUserNotFound
		}
		r, err = s.q.UserByID(ctx, value)
	case iam.UserKeyEmail:
		if value = contact.NormalizeEmail(value); value == "" {
			return iam.User{}, iam.ErrUserNotFound
		}
		r, err = s.q.UserByEmail(ctx, value)
	case iam.UserKeyPhone:
		if value = contact.NormalizePhone(value); value == "" {
			return iam.User{}, iam.ErrUserNotFound
		}
		r, err = s.q.UserByPhone(ctx, &value)
	case iam.UserKeyUsername:
		r, err = s.q.UserByUsername(ctx, value)
	default:
		return iam.User{}, iam.ErrUserNotFound
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.User{}, iam.ErrUserNotFound
	}
	if err != nil {
		return iam.User{}, err
	}
	if r.DeletedAt != nil && !o.IncludeDeleted {
		return iam.User{}, iam.ErrUserNotFound
	}
	return publicUser(&r, time.Now()), nil
}

// Users returns the accounts among ids, deleted ones included; unknown ids are
// absent. It is privileged: it carries contact details.
func (s *Engine) Users(ctx context.Context, ids []string) (map[string]iam.User, error) {
	out := map[string]iam.User{}
	ids = uuidsOnly(ids)
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > iam.MaxBatch {
		return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("ids"))
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	rows, err := s.q.UsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range rows {
		out[rows[i].ID] = publicUser(&rows[i], now)
	}
	return out, nil
}

// PublicUsers returns what others may see of ids. A deleted account is a
// tombstone; a banned one is returned normally (a ban is an access decision,
// not a visibility one); unknown ids are absent.
func (s *Engine) PublicUsers(ctx context.Context, ids []string) (map[string]iam.PublicUser, error) {
	out := map[string]iam.PublicUser{}
	ids = uuidsOnly(ids)
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > iam.MaxBatch {
		return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("ids"))
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	rows, err := s.q.IdentityPublicUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.DeletedAt != nil {
			out[r.ID] = iam.PublicUser{ID: r.ID, Deleted: true}
			continue
		}
		out[r.ID] = iam.PublicUser{ID: r.ID, Username: deref(r.Username), AvatarURL: deref(r.AvatarURL), CreatedAt: r.CreatedAt,
			Metadata: s.publicMetadata(r.Metadata)}
	}
	return out, nil
}

// publicMetadata keeps the Config.PublicUserMetadata keys of raw; nil when
// none are set.
func (s *Engine) publicMetadata(raw []byte) map[string]any {
	if len(s.cfg.PublicUserMetadata) == 0 || len(raw) == 0 {
		return nil
	}
	var all map[string]any
	if json.Unmarshal(raw, &all) != nil {
		return nil
	}
	var out map[string]any
	for _, k := range s.cfg.PublicUserMetadata {
		if v, ok := all[k]; ok {
			if out == nil {
				out = map[string]any{}
			}
			out[k] = v
		}
	}
	return out
}

func uuidsOnly(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); isUUID(id) {
			out = append(out, id)
		}
	}
	return out
}

// UserMetadata returns the account's application-owned metadata.
func (s *Engine) UserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if !isUUID(strings.TrimSpace(userID)) {
		return nil, iam.ErrUserNotFound
	}
	raw, err := s.q.UserMetadata(ctx, strings.TrimSpace(userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Sessions lists the account's live refresh sessions on this issuer.
func (s *Engine) Sessions(ctx context.Context, userID string) ([]iam.Session, error) {
	if !isUUID(strings.TrimSpace(userID)) {
		return nil, iam.ErrUserNotFound
	}
	rows, err := s.ListUserSessions(ctx, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	out := make([]iam.Session, 0, len(rows))
	for _, r := range rows {
		out = append(out, iam.Session{ID: r.ID, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, ExpiresAt: r.ExpiresAt, UserAgent: deref(r.UserAgent), IP: deref(r.IPAddr)})
	}
	return out, nil
}

// HasUsableMFA reports whether the account has 2FA enabled with a factor.
func (s *Engine) HasUsableMFA(ctx context.Context, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	return s.q.MFAUsable(ctx, userID)
}

// userCursor is ListUsers' keyset position: the last row's sort value and id,
// bound to the sort it was produced under.
type userCursor struct {
	Sort  iam.UserSort `json:"s"`
	Desc  bool         `json:"d"`
	Value *string      `json:"v,omitempty"`
	ID    string       `json:"i"`
}

func errInvalidCursor() error {
	return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("cursor"))
}

// userSortColumn maps a sort to its column and the cast its cursor value takes.
func userSortColumn(sort iam.UserSort) (col, cast string, ok bool) {
	switch sort {
	case "", iam.UserSortCreatedAt:
		return "u.created_at", "timestamptz", true
	case iam.UserSortLastLogin:
		return "u.last_login", "timestamptz", true
	case iam.UserSortUsername:
		return "u.username", "public.citext", true
	case iam.UserSortEmail:
		return "u.email", "public.citext", true
	}
	return "", "", false
}

// ListUsers is the user directory: search, status, root-role and entitlement
// filters, keyset-paged. NULL sort values come last in either direction. Each
// entry carries its root role and, with q.WithEntitlements, its entitlements;
// q.Total counts every match.
func (s *Engine) ListUsers(ctx context.Context, q iam.UserQuery) (iam.ListPage[iam.UserEntry], error) {
	page := iam.ListPage[iam.UserEntry]{Items: []iam.UserEntry{}}
	if err := s.requirePG(); err != nil {
		return page, err
	}
	col, cast, ok := userSortColumn(q.Sort)
	if !ok {
		return page, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("sort"))
	}
	if q.Sort == "" {
		q.Sort = iam.UserSortCreatedAt
	}
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	switch q.Status {
	case iam.UserStatusLive:
		where = append(where, "u.deleted_at IS NULL")
	case iam.UserStatusActive:
		where = append(where, "u.deleted_at IS NULL", "u.banned_at IS NULL")
	case iam.UserStatusBanned:
		where = append(where, "u.deleted_at IS NULL", "u.banned_at IS NOT NULL")
	case iam.UserStatusDeleted:
		where = append(where, "u.deleted_at IS NOT NULL")
	case iam.UserStatusAny:
	default:
		return page, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("status"))
	}
	if role := q.RootRole; !role.IsZero() {
		if role.Persona() != iam.RootPersona {
			return page, fmt.Errorf("root role filter %q is not a root role: %w", role, iam.ErrRoleNotAssignable)
		}
		where = append(where, `EXISTS (SELECT 1 FROM group_user_roles r JOIN permission_groups g ON g.id=r.permission_group_id
 WHERE r.user_id=u.id AND g.persona='root' AND r.role=`+arg(role.String())+`)`)
	}
	if search := strings.TrimSpace(q.Search); search != "" {
		p := arg("%" + search + "%")
		where = append(where, "(u.username ILIKE "+p+" OR u.email ILIKE "+p+" OR u.phone_number ILIKE "+p+")")
	}
	if ent := strings.TrimSpace(q.Entitlement); ent != "" {
		if s.entitlementHolders == nil {
			return page, errmodel.ErrEntitlementFilterUnavailable
		}
		subjects, err := s.entitlementHolders(ctx, ent)
		if err != nil {
			return page, fmt.Errorf("authkit: entitlement filter provider failed: %w", err)
		}
		where = append(where, "u.id::text = ANY("+arg(subjects)+"::text[])")
	}
	filters, filterArgs := len(where), len(args)
	cmp, dir := ">", "ASC"
	if q.Desc {
		cmp, dir = "<", "DESC"
	}
	if q.Page.Cursor != "" {
		c, err := decodeUserCursor(q.Page.Cursor)
		if err != nil || c.Sort != q.Sort || c.Desc != q.Desc || !isUUID(c.ID) {
			return page, errInvalidCursor()
		}
		id := arg(c.ID) + "::uuid"
		if c.Value == nil {
			where = append(where, "("+col+" IS NULL AND u.id "+cmp+" "+id+")")
		} else {
			v := arg(*c.Value) + "::" + cast
			where = append(where, "("+col+" "+cmp+" "+v+" OR ("+col+" = "+v+" AND u.id "+cmp+" "+id+") OR "+col+" IS NULL)")
		}
	}
	if q.Total {
		// The count ignores the keyset: it is taken before the cursor filter.
		n, err := s.countUsers(ctx, where[:filters], args[:filterArgs])
		if err != nil {
			return page, err
		}
		page.Total = &n
	}
	limit := q.Page.PageLimit()
	// The filters, sort column and keyset are built at runtime, so this query
	// only pages ids; the rows come from UsersByIDs, the one user projection.
	sql := `SELECT u.id::text, ` + col + `::text FROM users u WHERE ` + strings.Join(append([]string{"TRUE"}, where...), " AND ") +
		` ORDER BY ` + col + ` ` + dir + ` NULLS LAST, u.id ` + dir + ` LIMIT ` + arg(limit+1)
	rows, err := s.pg.Query(ctx, sql, args...)
	if err != nil {
		return page, err
	}
	var keys []userCursor
	for rows.Next() {
		c := userCursor{Sort: q.Sort, Desc: q.Desc}
		if err := rows.Scan(&c.ID, &c.Value); err != nil {
			rows.Close()
			return page, err
		}
		keys = append(keys, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(keys) > limit {
		keys = keys[:limit]
		page.Next = encodeUserCursor(keys[limit-1])
	}
	if len(keys) == 0 {
		return page, nil
	}
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ID
	}
	found, err := s.q.UsersByIDs(ctx, ids)
	if err != nil {
		return page, err
	}
	byID := make(map[string]*db.User, len(found))
	for i := range found {
		byID[found[i].ID] = &found[i]
	}
	now := time.Now()
	users := make([]iam.User, 0, len(keys))
	for _, k := range keys {
		if u := byID[k.ID]; u != nil { // absent when purged between the two reads
			users = append(users, publicUser(u, now))
		}
	}
	page.Items, err = s.userEntries(ctx, users, q.WithEntitlements)
	return page, err
}

// UserEntry is one account, deleted ones included, as the user directory
// lists it, entitlements included.
func (s *Engine) UserEntry(ctx context.Context, userID string) (iam.UserEntry, error) {
	u, err := s.User(ctx, iam.UserByID(userID), ops.IncludeDeleted())
	if err != nil {
		return iam.UserEntry{}, err
	}
	out, err := s.userEntries(ctx, []iam.User{u}, true)
	if err != nil {
		return iam.UserEntry{}, err
	}
	return out[0], nil
}

// userEntries adds each account's root role and, when asked, entitlements.
func (s *Engine) userEntries(ctx context.Context, users []iam.User, withEntitlements bool) ([]iam.UserEntry, error) {
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	roles, err := s.rootRoles(ctx, ids)
	if err != nil {
		return nil, err
	}
	var ents map[string][]string
	if withEntitlements {
		if ents, err = s.entitlementsOf(ctx, ids); err != nil {
			return nil, err
		}
	}
	out := make([]iam.UserEntry, len(users))
	for i, u := range users {
		out[i] = iam.UserEntry{User: u, RootRole: roles[u.ID], Entitlements: ents[u.ID]}
		if withEntitlements && out[i].Entitlements == nil {
			out[i].Entitlements = []string{}
		}
	}
	return out, nil
}

// countUsers counts the accounts matching where, a conjunction over args.
func (s *Engine) countUsers(ctx context.Context, where []string, args []any) (int, error) {
	var n int
	err := s.pg.QueryRow(ctx, `SELECT count(*) FROM users u WHERE `+strings.Join(append([]string{"TRUE"}, where...), " AND "), args...).Scan(&n)
	return n, err
}

// entitlementsOf asks the entitlements provider for ids' entitlements.
func (s *Engine) entitlementsOf(ctx context.Context, ids []string) (map[string][]string, error) {
	if s.entitlements == nil {
		return nil, nil
	}
	ents, err := s.entitlements(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("authkit: entitlements provider: %w", err)
	}
	return ents, nil
}

func encodeUserCursor(c userCursor) string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeUserCursor(s string) (userCursor, error) {
	var c userCursor
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(raw, &c)
	return c, err
}
