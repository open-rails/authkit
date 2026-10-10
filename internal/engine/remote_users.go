package engine

// A group's directory of its remote applications' users: the SCIM 2.0
// service provider (RFC 7643, RFC 7644) a remote application provisions, by
// its own token or an API key bound to it, and the reads of a library
// (UserInfo) and of the token path. A user is known by its issuer and
// subject, which only together identify it (OpenID Connect Core §2, §5.7).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/helpers/auth"
	"github.com/open-rails/helpers/userinfo"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/scim"
)

// RemoteUser is one user of a group's directory.
type RemoteUser struct {
	ID, GroupID, Issuer, Subject string
	Username, Name               string
	// Email is an address the issuer asserts: pushed over SCIM, or a
	// verified email claim.
	Email  string
	Active bool
	// ProvisionedAt is when a SCIM client created it; nil when only token
	// claims recorded it.
	ProvisionedAt        *time.Time
	CreatedAt, UpdatedAt time.Time
}

// RemoteUserClaims are an access token's contact claims (OpenID Connect
// Core §5.1). An empty one is absent.
type RemoteUserClaims struct {
	Email         string
	EmailVerified bool
	Name          string
	Username      string
	UpdatedAt     time.Time
}

// SCIMTenant is the directory who provisions (RFC 7644 §6.1: the tenant
// follows from the credential): an API key's, bound to a remote application
// of its group (iam.NewAPIKey.ProvisionsFor), or a remote application's own
// token's, whose group is boundGroup. The application must be enabled.
// Anything else is scim.ErrNoTenant.
func (s *Engine) SCIMTenant(ctx context.Context, who auth.Identity, boundGroup string) (scim.Tenant, error) {
	if err := s.requirePG(); err != nil {
		return scim.Tenant{}, err
	}
	switch {
	case who.Credential.Kind == auth.CredentialAPIKey:
		row, err := s.q.SCIMTenantByAPIKey(ctx, who.Credential.ID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return scim.Tenant{}, scim.ErrNoTenant
		case err != nil:
			return scim.Tenant{}, err
		case !row.Enabled || !row.SameGroup:
			return scim.Tenant{}, scim.ErrNoTenant
		}
		return s.scimTenant(row.GroupID, row.Persona, row.Issuer)
	case who.SubjectKind == auth.SubjectApplication && boundGroup != "" && who.Issuer != "" && who.Issuer != s.cfg.Token.Issuer:
		row, err := s.q.SCIMTenantByIssuer(ctx, who.Issuer)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return scim.Tenant{}, scim.ErrNoTenant
		case err != nil:
			return scim.Tenant{}, err
		case !row.Enabled || row.GroupID != boundGroup:
			return scim.Tenant{}, scim.ErrNoTenant
		}
		return s.scimTenant(row.GroupID, row.Persona, row.Issuer)
	}
	return scim.Tenant{}, scim.ErrNoTenant
}

// scimTenant is the tenant of a persona that still has remote applications.
func (s *Engine) scimTenant(group, persona, issuer string) (scim.Tenant, error) {
	if p, ok := s.groupSchemaOrDefault().Persona(ident.Persona(persona)); !ok || !p.RemoteApplications {
		return scim.Tenant{}, scim.ErrNoTenant
	}
	return scim.Tenant{GroupID: group, Persona: persona, Issuer: issuer}, nil
}

var errNoUser = scim.Fail(http.StatusNotFound, "", "no such user")

// DirectoryUser is the tenant's provisioned user id.
func (s *Engine) DirectoryUser(ctx context.Context, t scim.Tenant, id string) (scim.User, error) {
	if err := s.requirePG(); err != nil {
		return scim.User{}, err
	}
	id, ok := canonicalUUID(id)
	if !ok {
		return scim.User{}, errNoUser
	}
	row, err := s.q.RemoteUserProvisioned(ctx, db.RemoteUserProvisionedParams{ID: id, GroupID: t.GroupID, Issuer: t.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return scim.User{}, errNoUser
	}
	if err != nil {
		return scim.User{}, err
	}
	return directoryUser(row), nil
}

// DirectoryUsers answers a query of the tenant's provisioned users: those
// filter matches (scim.ParseFilter), or all, in id order, from the 1-based
// startIndex (RFC 7644 §3.4.2).
func (s *Engine) DirectoryUsers(ctx context.Context, t scim.Tenant, filter string, startIndex, count int) (scim.ListResponse[scim.User], error) {
	out := scim.ListResponse[scim.User]{Schemas: []string{scim.SchemaListResponse}, StartIndex: max(startIndex, 1), Resources: []scim.User{}}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	count = min(max(count, 0), scim.MaxResults)
	var rows []db.RemoteUser
	if strings.TrimSpace(filter) == "" {
		total, err := s.q.RemoteUsersCount(ctx, db.RemoteUsersCountParams{GroupID: t.GroupID, Issuer: t.Issuer})
		if err != nil {
			return out, err
		}
		out.TotalResults = int(total)
		if count > 0 {
			rows, err = s.q.RemoteUsersPage(ctx, db.RemoteUsersPageParams{GroupID: t.GroupID, Issuer: t.Issuer, PageSize: int64(count), Skip: int64(out.StartIndex - 1)})
			if err != nil {
				return out, err
			}
		}
	} else {
		f, err := scim.ParseFilter(filter)
		if err != nil {
			return out, err
		}
		ids := []string{}
		for _, id := range f.IDs {
			if id, ok := canonicalUUID(id); ok {
				ids = append(ids, id)
			}
		}
		matched, err := s.q.RemoteUsersMatching(ctx, db.RemoteUsersMatchingParams{
			GroupID: t.GroupID, Issuer: t.Issuer, Ids: ids, Subjects: nonNil(f.ExternalIDs), UserNames: nonNil(f.UserNames), Emails: nonNil(f.Emails),
		})
		if err != nil {
			return out, err
		}
		out.TotalResults = len(matched)
		from := min(out.StartIndex-1, len(matched))
		rows = matched[from:min(from+count, len(matched))]
	}
	for _, row := range rows {
		out.Resources = append(out.Resources, directoryUser(row))
	}
	out.ItemsPerPage = len(out.Resources)
	return out, nil
}

// CreateDirectoryUser creates u in the tenant (RFC 7644 §3.3). A user its
// token claims recorded becomes provisioned; one already provisioned, or a
// userName another holds, is 409 uniqueness.
func (s *Engine) CreateDirectoryUser(ctx context.Context, t scim.Tenant, u scim.User) (scim.User, error) {
	if err := s.requirePG(); err != nil {
		return scim.User{}, err
	}
	d, err := u.Directory()
	if err != nil {
		return scim.User{}, err
	}
	row, err := s.q.RemoteUserCreate(ctx, db.RemoteUserCreateParams{
		GroupID: t.GroupID, Issuer: t.Issuer, Subject: d.Subject, UserName: d.UserName, DisplayName: nullable(d.DisplayName),
		NameFormatted: nullable(d.Formatted), GivenName: nullable(d.GivenName), FamilyName: nullable(d.FamilyName),
		Email: nullable(d.Email), EmailType: nullable(d.EmailType), Active: d.Active,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return scim.User{}, scim.Fail(http.StatusConflict, "uniqueness", "a user with this externalId exists")
	}
	if err != nil {
		return scim.User{}, directoryWriteError(err)
	}
	return directoryUser(row), nil
}

// ReplaceDirectoryUser replaces the tenant's user id with u (RFC 7644
// §3.5.1): what u omits is cleared, id and meta are ignored.
func (s *Engine) ReplaceDirectoryUser(ctx context.Context, t scim.Tenant, id string, u scim.User) (scim.User, error) {
	if err := s.requirePG(); err != nil {
		return scim.User{}, err
	}
	d, err := u.Directory()
	if err != nil {
		return scim.User{}, err
	}
	id, ok := canonicalUUID(id)
	if !ok {
		return scim.User{}, errNoUser
	}
	row, err := s.q.RemoteUserReplace(ctx, replaceParams(t, id, d))
	if errors.Is(err, pgx.ErrNoRows) {
		return scim.User{}, errNoUser
	}
	if err != nil {
		return scim.User{}, directoryWriteError(err)
	}
	return directoryUser(row), nil
}

// PatchDirectoryUser applies req to the tenant's user id (RFC 7644 §3.5.2),
// all operations or none.
func (s *Engine) PatchDirectoryUser(ctx context.Context, t scim.Tenant, id string, req scim.PatchRequest) (scim.User, error) {
	if err := s.requirePG(); err != nil {
		return scim.User{}, err
	}
	id, ok := canonicalUUID(id)
	if !ok {
		return scim.User{}, errNoUser
	}
	var out scim.User
	err := pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		q := s.qtx(tx)
		row, err := q.RemoteUserProvisionedForUpdate(ctx, db.RemoteUserProvisionedForUpdateParams{ID: id, GroupID: t.GroupID, Issuer: t.Issuer})
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoUser
		}
		if err != nil {
			return err
		}
		u := directoryUser(row)
		if err := req.Apply(&u); err != nil {
			return err
		}
		d, err := u.Directory()
		if err != nil {
			return err
		}
		row, err = q.RemoteUserReplace(ctx, replaceParams(t, id, d))
		if err != nil {
			return directoryWriteError(err)
		}
		out = directoryUser(row)
		return nil
	})
	return out, err
}

// DeleteDirectoryUser deletes the tenant's user id and everything kept of it
// (RFC 7644 §3.6).
func (s *Engine) DeleteDirectoryUser(ctx context.Context, t scim.Tenant, id string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	id, ok := canonicalUUID(id)
	if !ok {
		return errNoUser
	}
	n, err := s.q.RemoteUserDelete(ctx, db.RemoteUserDeleteParams{ID: id, GroupID: t.GroupID, Issuer: t.Issuer})
	if err == nil && n == 0 {
		err = errNoUser
	}
	return err
}

// RemoteUser is the group's user of issuer known by subject, provisioned or
// recorded from claims; iam.ErrUserNotFound when there is none.
func (s *Engine) RemoteUser(ctx context.Context, groupID, issuer, subject string) (RemoteUser, error) {
	if err := s.requirePG(); err != nil {
		return RemoteUser{}, err
	}
	groupID, ok := canonicalUUID(groupID)
	if !ok {
		return RemoteUser{}, iam.ErrUserNotFound
	}
	row, err := s.q.RemoteUserBySubject(ctx, db.RemoteUserBySubjectParams{GroupID: groupID, Issuer: issuer, Subject: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return RemoteUser{}, iam.ErrUserNotFound
	}
	if err != nil {
		return RemoteUser{}, err
	}
	d := directoryOf(row)
	return RemoteUser{
		ID: row.ID, GroupID: row.PermissionGroupID, Issuer: row.Issuer, Subject: row.Subject, Username: d.UserName, Name: d.Name(),
		Email: d.Email, Active: row.Active, ProvisionedAt: row.ProvisionedAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// RecordRemoteUserClaims records a verified token's contact claims for the
// group's user of issuer known by subject: a new user's at once; a held
// one's only when c.UpdatedAt is after what it holds and something changed,
// so a token that repeats them writes nothing. An email counts only when
// verified; a claim that is empty or too long is absent and keeps the held
// value.
func (s *Engine) RecordRemoteUserClaims(ctx context.Context, groupID, issuer, subject string, c RemoteUserClaims) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	groupID, ok := canonicalUUID(groupID)
	subject = strings.TrimSpace(subject)
	if !ok || issuer == "" || subject == "" || utf8.RuneCountInString(subject) > scim.MaxSubject {
		return nil
	}
	email := bounded(c.Email, scim.MaxEmail)
	if !c.EmailVerified {
		email = nil
	}
	name, username := bounded(c.Name, scim.MaxName), bounded(c.Username, scim.MaxName)
	if email == nil && name == nil && username == nil {
		return nil
	}
	var at *time.Time
	if !c.UpdatedAt.IsZero() {
		t := c.UpdatedAt.UTC()
		at = &t
	}
	return s.q.RemoteUserRecordClaims(ctx, db.RemoteUserRecordClaimsParams{
		GroupID: groupID, Issuer: issuer, Subject: subject, UserName: username, DisplayName: name, Email: email, ClaimsUpdatedAt: at,
	})
}

// RemoteUserInfo returns the active users among subjects of the group's
// directory of issuer, keyed by subject; an inactive or unknown one is
// absent.
func (s *Engine) RemoteUserInfo(ctx context.Context, groupID, issuer string, subjects []string) (map[string]userinfo.User, error) {
	out := map[string]userinfo.User{}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	if len(subjects) == 0 {
		return out, nil
	}
	rows, err := s.q.RemoteUsersBySubjects(ctx, db.RemoteUsersBySubjectsParams{GroupID: groupID, Issuer: issuer, Subjects: subjects})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.Subject] = remoteUserInfo(row)
	}
	return out, nil
}

// SearchRemoteUserInfo returns up to limit active users of the group's
// directory of issuer whose username, email or name contains query, ignoring
// case.
func (s *Engine) SearchRemoteUserInfo(ctx context.Context, groupID, issuer, query string, limit int) ([]userinfo.User, error) {
	out := []userinfo.User{}
	if query == "" || limit < 1 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	rows, err := s.q.RemoteUsersSearch(ctx, db.RemoteUsersSearchParams{
		GroupID: groupID, Issuer: issuer, Pattern: "%" + likeEscaper.Replace(strings.ToLower(query)) + "%", MaxRows: int64(min(limit, 1000)),
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, remoteUserInfo(row))
	}
	return out, nil
}

func remoteUserInfo(row db.RemoteUser) userinfo.User {
	d := directoryOf(row)
	return userinfo.User{ID: row.Subject, Email: d.Email, Name: d.Name(), Username: d.UserName}
}

func directoryOf(row db.RemoteUser) scim.DirectoryUser {
	return scim.DirectoryUser{
		Subject: row.Subject, UserName: deref(row.UserName), DisplayName: deref(row.DisplayName), Formatted: deref(row.NameFormatted),
		GivenName: deref(row.GivenName), FamilyName: deref(row.FamilyName), Email: deref(row.Email), EmailType: deref(row.EmailType), Active: row.Active,
	}
}

// directoryUser is a provisioned row as its SCIM User.
func directoryUser(row db.RemoteUser) scim.User {
	d := directoryOf(row)
	active := row.Active
	modified := row.UpdatedAt.UTC()
	u := scim.User{
		Schemas: []string{scim.SchemaUser}, ID: row.ID, ExternalID: row.Subject, UserName: d.UserName, DisplayName: d.DisplayName,
		Active: &active, Meta: &scim.Meta{ResourceType: "User", LastModified: &modified},
	}
	if row.ProvisionedAt != nil {
		created := row.ProvisionedAt.UTC()
		u.Meta.Created = &created
	}
	if d.Formatted != "" || d.GivenName != "" || d.FamilyName != "" {
		u.Name = &scim.Name{Formatted: d.Formatted, GivenName: d.GivenName, FamilyName: d.FamilyName}
	}
	if d.Email != "" {
		u.Emails = []scim.Email{{Value: d.Email, Type: d.EmailType, Primary: true}}
	}
	return u
}

func replaceParams(t scim.Tenant, id string, d scim.DirectoryUser) db.RemoteUserReplaceParams {
	return db.RemoteUserReplaceParams{
		ID: id, GroupID: t.GroupID, Issuer: t.Issuer, Subject: d.Subject, UserName: d.UserName, DisplayName: nullable(d.DisplayName),
		NameFormatted: nullable(d.Formatted), GivenName: nullable(d.GivenName), FamilyName: nullable(d.FamilyName),
		Email: nullable(d.Email), EmailType: nullable(d.EmailType), Active: d.Active,
	}
}

// directoryWriteError is a write's uniqueness violation as SCIM's 409
// (RFC 7644 §3.3, §3.12).
func directoryWriteError(err error) error {
	switch {
	case isUniqueViolation(err, "remote_users_user_name_key"):
		return scim.Fail(http.StatusConflict, "uniqueness", "another user has this userName")
	case isUniqueViolation(err, "remote_users_subject_key"):
		return scim.Fail(http.StatusConflict, "uniqueness", "another user has this externalId")
	}
	return err
}

// bounded is a claim the directory can hold: trimmed, nil when blank or
// longer than limit.
func bounded(s string, limit int) *string {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > limit {
		return nil
	}
	return &s
}
