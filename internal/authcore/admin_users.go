package authcore

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"strings"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Admin user directory: the dashboard list/count/get, account recovery, and hard
// delete. The list and count share one runtime-assembled, fully-parameterized
// query (adminUserDirectoryQuery); ordering is a closed enum.

type AdminUser = authkit.AdminUser

// AdminListUsersResult contains paginated user list with total count
type AdminListUsersResult = authkit.AdminListUsersResult

// AdminUserStatus filters the directory by account state.
type AdminUserStatus = authkit.AdminUserStatus

const (
	AdminUserStatusActive  = authkit.AdminUserStatusActive
	AdminUserStatusBanned  = authkit.AdminUserStatusBanned
	AdminUserStatusDeleted = authkit.AdminUserStatusDeleted
	AdminUserStatusAny     = authkit.AdminUserStatusAny
	// "" (zero value) defaults to non-deleted (the historical "All users" behavior).
)

// AdminUserSort selects the directory ordering column.
type AdminUserSort = authkit.AdminUserSort

const (
	AdminUserSortCreatedAt = authkit.AdminUserSortCreatedAt
	AdminUserSortLastLogin = authkit.AdminUserSortLastLogin
	AdminUserSortUsername  = authkit.AdminUserSortUsername
	AdminUserSortEmail     = authkit.AdminUserSortEmail
)

// AdminUserListOptions is the admin dashboard user-directory query. It carries
// no host product knowledge: Role is the root_role query param, a singleton-root
// permission-group role slug. Status/Sort are closed enums. Entitlement
// filtering delegates to the billing provider, never a cross-schema join.
type AdminUserListOptions = authkit.AdminUserListOptions

// ErrEntitlementFilterUnavailable is returned by AdminListUsers/AdminCountUsers
// when an Entitlement filter is requested but no EntitlementFilterProvider is
// configured — fail loud rather than silently return everyone.
var ErrEntitlementFilterUnavailable = authkit.ErrEntitlementFilterUnavailable

func normalizeAdminUserListOptions(o AdminUserListOptions) AdminUserListOptions {
	if o.Page <= 0 {
		o.Page = 1
	}
	if o.PageSize <= 0 || o.PageSize > 200 {
		o.PageSize = 50
	}
	return o
}

// adminUserDirectoryQuery builds the shared FROM + WHERE + args for the directory
// list and count (no ORDER BY / pagination). When an Entitlement filter is set it
// resolves the subject set via the provider HERE, so list and count agree and the
// provider is hit once per call.
func (s *Service) adminUserDirectoryQuery(ctx context.Context, o AdminUserListOptions) (from string, where []string, args []any, err error) {
	from = "profiles.users u"
	args = []any{}
	argIdx := 1

	switch o.Status {
	case AdminUserStatusActive:
		where = append(where, "u.deleted_at IS NULL", "u.banned_at IS NULL")
	case AdminUserStatusBanned:
		where = append(where, "u.deleted_at IS NULL", "u.banned_at IS NOT NULL")
	case AdminUserStatusDeleted:
		where = append(where, "u.deleted_at IS NOT NULL")
	case AdminUserStatusAny:
		// no deleted/banned predicate
	default:
		where = append(where, "u.deleted_at IS NULL")
	}

	if slug := strings.TrimSpace(o.Role); slug != "" {
		// root_role filters on a user's role in the singleton root group. Use
		// WHERE EXISTS (not a JOIN) so the result is one row per user — no
		// duplication, so no SELECT DISTINCT is needed and the (col, id) sort can
		// use an index.
		slug = normalizeRootRoleSlug(slug)
		where = append(where, "EXISTS (SELECT 1 FROM profiles.group_user_roles gur"+
			" JOIN profiles.permission_groups pg ON pg.id = gur.permission_group_id"+
			" WHERE gur.user_id = u.id AND gur.deleted_at IS NULL AND gur.role = $"+fmt.Sprint(argIdx)+
			" AND pg.persona = 'root')")
		args = append(args, slug)
		argIdx++
	}

	if search := strings.TrimSpace(o.Search); search != "" {
		where = append(where, "(u.username ILIKE $"+fmt.Sprint(argIdx)+" OR u.email ILIKE $"+fmt.Sprint(argIdx)+" OR u.phone_number ILIKE $"+fmt.Sprint(argIdx)+")")
		args = append(args, "%"+search+"%")
		argIdx++
	}

	if ent := strings.TrimSpace(o.Entitlement); ent != "" {
		fp, ok := s.entitlements.(EntitlementFilterProvider)
		if !ok {
			return "", nil, nil, ErrEntitlementFilterUnavailable
		}
		subjects, ferr := fp.ListSubjectsWithEntitlement(ctx, ent)
		if ferr != nil {
			return "", nil, nil, fmt.Errorf("authkit: entitlement filter provider failed: %w", ferr)
		}
		where = append(where, "u.id::text = ANY($"+fmt.Sprint(argIdx)+"::text[])")
		args = append(args, subjects)
		argIdx++
	}

	if len(where) == 0 {
		where = append(where, "TRUE")
	}
	return from, where, args, nil
}

// adminUserOrderBy renders a safe ORDER BY (closed enum) with a stable id
// tiebreaker. The id tiebreaker is the raw uuid (not ::text) so the (col, id)
// admin indexes can serve the ordering; uuidv7 byte order matches the canonical
// string's lexical order, so the row order is unchanged from the prior ::text cast.
func adminUserOrderBy(o AdminUserListOptions) string {
	col := "u.created_at"
	switch o.Sort {
	case AdminUserSortLastLogin:
		col = "u.last_login"
	case AdminUserSortUsername:
		col = "u.username"
	case AdminUserSortEmail:
		col = "u.email"
	}
	dir := "ASC"
	if o.Desc {
		dir = "DESC"
	}
	return col + " " + dir + ", u.id " + dir
}

// adminUserCount runs the directory COUNT for a from/where/args triple produced by
// adminUserDirectoryQuery. Shared by AdminCountUsers and AdminListUsers so the
// count SQL has one definition and both agree on the predicate set.
func (s *Service) adminUserCount(ctx context.Context, from string, where []string, args []any) (int64, error) {
	q := db.RewriteSQL("SELECT COUNT(DISTINCT u.id) FROM "+from+" WHERE "+strings.Join(where, " AND "), s.dbSchema())
	var total int64
	if err := s.pg.QueryRow(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// AdminCountUsers returns the number of users matching opts (same filters as
// AdminListUsers, ignoring pagination/sort).
func (s *Service) AdminCountUsers(ctx context.Context, opts AdminUserListOptions) (int64, error) {
	if s.pg == nil {
		return 0, nil
	}
	from, where, args, err := s.adminUserDirectoryQuery(ctx, opts)
	if err != nil {
		return 0, err
	}
	return s.adminUserCount(ctx, from, where, args)
}

// AdminListUsers is the generic admin user-directory list (issue #91): generic
// role/status filter + search + sort + offset pagination, with optional
// provider-backed entitlement filtering. Each row is enriched with role slugs
// and (via the entitlements provider) entitlement names.
func (s *Service) AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error) {
	opts = normalizeAdminUserListOptions(opts)
	if s.pg == nil {
		return &AdminListUsersResult{Users: []AdminUser{}, Total: 0, Limit: opts.PageSize, Offset: 0}, nil
	}
	offset := (opts.Page - 1) * opts.PageSize

	from, where, args, err := s.adminUserDirectoryQuery(ctx, opts)
	if err != nil {
		return nil, err
	}

	total, err := s.adminUserCount(ctx, from, where, args)
	if err != nil {
		return nil, err
	}

	// Intentionally raw pgx (not sqlc): the filter/search/pagination clauses are
	// assembled at runtime, which sqlc's static compilation cannot express.
	// Written against the default "profiles." qualifier and rewritten to the
	// configured schema, same mechanism as the sqlc path (issue 69).
	argIdx := len(args) + 1
	selectCols := "u.id::text, u.email, u.phone_number, u.username, u.email_verified, u.phone_verified, u.banned_at, u.banned_until, u.ban_reason, u.banned_by, u.deleted_at, u.biography, u.created_at, u.updated_at, u.last_login"
	query := "SELECT " + selectCols + " FROM " + from + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + adminUserOrderBy(opts) + " OFFSET $" + fmt.Sprint(argIdx) + " LIMIT $" + fmt.Sprint(argIdx+1)
	args = append(args, offset, opts.PageSize)

	rows, err := s.pg.Query(ctx, db.RewriteSQL(query, s.dbSchema()), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUser
	for rows.Next() {
		var a AdminUser
		if err := rows.Scan(&a.ID, &a.Email, &a.PhoneNumber, &a.Username, &a.EmailVerified, &a.PhoneVerified, &a.BannedAt, &a.BannedUntil, &a.BanReason, &a.BannedBy, &a.DeletedAt, &a.Biography, &a.CreatedAt, &a.UpdatedAt, &a.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Enrich root-group roles for the whole page in ONE query instead of two per
	// row. Resolution failures degrade to empty roles (matching the prior
	// per-row swallow), so the listing still renders.
	if len(out) > 0 {
		st := s.groupStore()
		if gid, gErr := st.RootGroupID(ctx); gErr == nil {
			ids := make([]string, len(out))
			for i := range out {
				ids[i] = out[i].ID
			}
			if rolesByUser, rErr := st.RootRolesForUsers(ctx, gid, ids); rErr == nil {
				for i := range out {
					out[i].Roles, out[i].RemovedRoles = s.splitConfiguredRootRoles(rolesByUser[out[i].ID])
				}
			}
		}
	}
	s.enrichEntitlements(ctx, out)
	return &AdminListUsersResult{Users: out, Total: total, Limit: opts.PageSize, Offset: offset}, nil
}

// enrichEntitlements fills Entitlements for a page of users in ONE provider
// call (the provider is batch-native, #221). Provider failures log and degrade
// to no entitlements.
func (s *Service) enrichEntitlements(ctx context.Context, users []AdminUser) {
	if s.entitlements == nil || len(users) == 0 {
		return
	}
	ids := make([]string, 0, len(users))
	for i := range users {
		ids = append(ids, users[i].ID)
	}
	ents, err := s.entitlements.ListEntitlements(ctx, ids)
	if err != nil {
		stdlog.Printf("authkit: error: batch entitlements provider failed for %d users; reporting no entitlements: %v", len(users), err)
		return
	}
	for i := range users {
		users[i].Entitlements = ents[users[i].ID]
	}
}

func (s *Service) AdminGetUser(ctx context.Context, id string) (*AdminUser, error) {
	u, err := s.getUserByID(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	a := &AdminUser{
		ID: u.ID, Email: u.Email, PhoneNumber: u.PhoneNumber, Username: u.Username, DiscordUsername: u.DiscordUsername,
		EmailVerified: u.EmailVerified, PhoneVerified: u.PhoneVerified,
		BannedAt: u.BannedAt, BannedUntil: u.BannedUntil, BanReason: u.BanReason, BannedBy: u.BannedBy, DeletedAt: u.DeletedAt,
		Biography: u.Biography, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, LastLogin: u.LastLogin,
		PreferredLanguage: u.PreferredLanguage,
	}
	a.Roles, a.RemovedRoles = s.rootRoleSlugsByUser(ctx, id)
	a.Entitlements = s.ListEntitlements(ctx, id)
	return a, nil
}

type AdminRecoverUserInput struct {
	Email       string
	PhoneNumber string
}

// AdminRecoverUser locks down a compromised account and replaces its primary
// recovery identifier before sending a password-reset link/code to that new
// identifier.
func (s *Service) AdminRecoverUser(ctx context.Context, userID string, input AdminRecoverUserInput) error {
	if s.pg == nil {
		return nil
	}
	userID = strings.TrimSpace(userID)
	email := NormalizeEmail(input.Email)
	phone := NormalizePhone(input.PhoneNumber)
	if userID == "" || (email == "") == (phone == "") {
		return fmt.Errorf("invalid_request")
	}
	if email != "" {
		if err := ValidateEmail(email); err != nil {
			return err
		}
		if !s.HasEmailSender() {
			return ErrEmailSenderUnavailable
		}
		existing, err := s.getUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if existing != nil && strings.TrimSpace(existing.ID) != userID {
			return ErrEmailInUse
		}
	} else {
		if err := ValidatePhone(phone); err != nil {
			return err
		}
		if !s.HasSMSSender() {
			return ErrSMSSenderUnavailable
		}
		existing, err := s.GetUserByPhone(ctx, phone)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if existing != nil && strings.TrimSpace(existing.ID) != userID {
			return ErrPhoneInUse
		}
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	if _, err := qtx.UserByID(ctx, userID); errors.Is(err, pgx.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}

	sessionIDs, err := qtx.SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: userID, Issuer: s.cfg.Token.Issuer})
	if err != nil {
		return err
	}
	if err := qtx.UserPasswordDelete(ctx, userID); err != nil {
		return err
	}
	if err := qtx.UserProvidersDeleteByUser(ctx, userID); err != nil {
		return err
	}
	if err := qtx.MFADelete(ctx, userID); err != nil {
		return err
	}
	if err := qtx.UserClearLoginIdentifiers(ctx, userID); err != nil {
		return err
	}
	if email != "" {
		if err := qtx.UserSetEmailAndVerified(ctx, db.UserSetEmailAndVerifiedParams{ID: userID, Email: email}); err != nil {
			return err
		}
	} else {
		verified := true
		if err := qtx.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: userID, PhoneNumber: &phone, PhoneVerified: verified}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	reason := string(SessionRevokeReasonAdminRevokeAll)
	for _, sessionID := range sessionIDs {
		s.logSessionRevoked(ctx, userID, sessionID, &reason)
	}
	if email != "" {
		return s.RequestPasswordReset(ctx, email, 0, nil, nil)
	}
	return s.RequestPhonePasswordReset(ctx, phone, 0, nil, nil)
}

func (s *Service) AdminDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	// Revoke all sessions
	_ = s.q.SessionsRevokeAllQuiet(ctx, db.SessionsRevokeAllQuietParams{UserID: id, Issuer: s.cfg.Token.Issuer})
	if err := s.q.GroupAssignmentsDeleteByUser(ctx, id); err != nil {
		return err
	}
	// Delete user
	return s.q.UserDeleteHard(ctx, id)
}
