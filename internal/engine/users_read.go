package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Account reads. They take no actor: the host is the trust boundary, and
// httpapi gates its read routes with root:users:read.

// userColumns selects a userRecord plus the reserved flag, in scanUser order.
const userColumns = `u.id::text, u.email::text, u.phone_number, u.username::text, u.email_verified, u.phone_verified,
 u.banned_at, u.banned_until, u.ban_reason, u.banned_by::text, u.deleted_at, u.created_at, u.updated_at, u.last_login,
 u.preferred_language, u.avatar_url,
 COALESCE(jsonb_typeof(u.metadata->'reserved')='boolean' AND (u.metadata->>'reserved')::boolean, false)`

func scanUser(row pgx.Row) (*userRecord, bool, error) {
	var r userRecord
	var reserved bool
	err := row.Scan(&r.ID, &r.Email, &r.PhoneNumber, &r.Username, &r.EmailVerified, &r.PhoneVerified,
		&r.BannedAt, &r.BannedUntil, &r.BanReason, &r.BannedBy, &r.DeletedAt, &r.CreatedAt, &r.UpdatedAt, &r.LastLogin,
		&r.PreferredLanguage, &r.AvatarURL, &reserved)
	return &r, reserved, err
}

// User returns one account. Soft-deleted accounts are excluded unless opts
// include iam.IncludeDeleted(); a miss is iam.ErrUserNotFound.
func (s *Engine) User(ctx context.Context, ref iam.UserRef, opts ...iam.ReadOption) (iam.User, error) {
	if err := s.requirePG(); err != nil {
		return iam.User{}, err
	}
	var where string
	value := ref.Value()
	switch ref.Key() {
	case iam.UserKeyID:
		if !isUUID(value) {
			return iam.User{}, iam.ErrUserNotFound
		}
		where = `u.id=$1::uuid`
	case iam.UserKeyEmail:
		value, where = contact.NormalizeEmail(value), `u.email=lower($1::text)::public.citext`
	case iam.UserKeyPhone:
		value, where = contact.NormalizePhone(value), `u.phone_number=$1`
	case iam.UserKeyUsername:
		where = `u.username=$1::text::public.citext`
	}
	if where == "" || value == "" {
		return iam.User{}, iam.ErrUserNotFound
	}
	if !iam.IncludesDeleted(opts) {
		where += ` AND u.deleted_at IS NULL`
	}
	r, reserved, err := scanUser(s.pg.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE `+where, value))
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.User{}, iam.ErrUserNotFound
	}
	if err != nil {
		return iam.User{}, err
	}
	return r.public(reserved, time.Now()), nil
}

// Users returns the accounts among ids, deleted ones included; unknown ids are
// absent. It is privileged (it carries contact details) and is verify's
// liveness source: Live is the same gate login and refresh apply.
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
	rows, err := s.pg.Query(ctx, `SELECT `+userColumns+` FROM users u WHERE u.id=ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		r, reserved, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out[r.ID] = r.public(reserved, now)
	}
	return out, rows.Err()
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
		out[r.ID] = iam.PublicUser{ID: r.ID, Username: deref(r.Username), AvatarURL: deref(r.AvatarUrl), CreatedAt: r.CreatedAt}
	}
	return out, nil
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
	var ok bool
	err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_settings m WHERE m.user_id=$1::uuid AND m.enabled
 AND EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id=m.user_id))`, userID).Scan(&ok)
	return ok, err
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
// filters, keyset-paged. NULL sort values come last in either direction.
func (s *Engine) ListUsers(ctx context.Context, q iam.UserQuery) (iam.ListPage[iam.User], error) {
	page := iam.ListPage[iam.User]{Items: []iam.User{}}
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
 WHERE r.user_id=u.id AND g.persona='root' AND r.role=`+arg(role.Name())+`)`)
	}
	if search := strings.TrimSpace(q.Search); search != "" {
		p := arg("%" + search + "%")
		where = append(where, "(u.username ILIKE "+p+" OR u.email ILIKE "+p+" OR u.phone_number ILIKE "+p+")")
	}
	if ent := strings.TrimSpace(q.Entitlement); ent != "" {
		fp, ok := s.entitlementsProvider().(entitlementFilterProvider)
		if !ok {
			return page, errmodel.ErrEntitlementFilterUnavailable
		}
		subjects, err := fp.ListSubjectsWithEntitlement(ctx, ent)
		if err != nil {
			return page, fmt.Errorf("authkit: entitlement filter provider failed: %w", err)
		}
		where = append(where, "u.id::text = ANY("+arg(subjects)+"::text[])")
	}
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
	if len(where) == 0 {
		where = append(where, "TRUE")
	}
	limit := q.Page.PageLimit()
	sql := `SELECT ` + userColumns + `, ` + col + `::text FROM users u WHERE ` + strings.Join(where, " AND ") +
		` ORDER BY ` + col + ` ` + dir + ` NULLS LAST, u.id ` + dir + ` LIMIT ` + arg(limit+1)
	rows, err := s.pg.Query(ctx, sql, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	now := time.Now()
	var last userCursor
	for rows.Next() {
		var r userRecord
		var reserved bool
		var sortValue *string
		if err := rows.Scan(&r.ID, &r.Email, &r.PhoneNumber, &r.Username, &r.EmailVerified, &r.PhoneVerified,
			&r.BannedAt, &r.BannedUntil, &r.BanReason, &r.BannedBy, &r.DeletedAt, &r.CreatedAt, &r.UpdatedAt, &r.LastLogin,
			&r.PreferredLanguage, &r.AvatarURL, &reserved, &sortValue); err != nil {
			return page, err
		}
		if len(page.Items) == limit {
			page.Next = encodeUserCursor(last)
			break
		}
		page.Items = append(page.Items, r.public(reserved, now))
		last = userCursor{Sort: q.Sort, Desc: q.Desc, Value: sortValue, ID: r.ID}
	}
	return page, rows.Err()
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

// UserDirectoryDetails adds, for httpapi's admin views, each user's root
// roles and entitlements. Lookup failures degrade to empty details.
func (s *Engine) UserDirectoryDetails(ctx context.Context, ids []string) map[string]authflow.UserDirectoryDetail {
	out := make(map[string]authflow.UserDirectoryDetail, len(ids))
	ids = uuidsOnly(ids)
	if len(ids) == 0 || s.pg == nil {
		return out
	}
	st := s.groupStore()
	if gid, err := st.RootGroupID(ctx); err == nil {
		if roles, err := st.RootRolesForUsers(ctx, gid, ids); err == nil {
			for _, id := range ids {
				d := out[id]
				d.Roles, d.RemovedRoles = s.splitConfiguredRootRoles(roles[id])
				out[id] = d
			}
		}
	}
	if provider := s.entitlementsProvider(); provider != nil {
		ents, err := provider.ListEntitlements(ctx, ids)
		if err != nil {
			stdlog.Printf("authkit: error: batch entitlements provider failed for %d users; reporting no entitlements: %v", len(ids), err)
		}
		for _, id := range ids {
			d := out[id]
			d.Entitlements = ents[id]
			out[id] = d
		}
	}
	return out
}
