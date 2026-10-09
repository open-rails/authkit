package engine

// Group reads.

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cursor"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
)

// Group reads one group, a soft-deleted one included, with DeletedAt set.
// Absence is ErrGroupNotFound.
func (s *Engine) Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error) {
	if err := s.requirePG(); err != nil {
		return iam.Group{}, err
	}
	st := s.groupStore()
	id := ref.ID()
	if ref.IsRoot() {
		var err error
		if id, err = s.rootGroup(ctx, st); err != nil {
			return iam.Group{}, err
		}
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return iam.Group{}, iam.ErrGroupNotFound
	}
	return st.groupByID(ctx, u.String())
}

// RootGroupID is the root group's id.
func (s *Engine) RootGroupID(ctx context.Context) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	return s.rootGroup(ctx, s.groupStore())
}

// Groups reads many groups by id, soft-deleted ones included. Unknown ids
// are absent.
func (s *Engine) Groups(ctx context.Context, ids []string) (map[string]iam.Group, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	return s.groupStore().groupsByID(ctx, ids)
}

// ListGroups lists groups oldest first. The root group is never listed.
// q.Ownerless keeps live groups with no owner that counts toward the
// last-owner rule (requireRemainingOwner).
func (s *Engine) ListGroups(ctx context.Context, q iam.GroupQuery) (iam.ListPage[iam.Group], error) {
	var out iam.ListPage[iam.Group]
	if err := s.requirePG(); err != nil {
		return out, err
	}
	persona := q.Persona
	if _, ok := s.groupSchemaOrDefault().Persona(persona); !persona.IsZero() && (!ok || persona == iam.RootPersona()) {
		return out, fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	after, err := cursor.Keys(q.Page.Cursor, 1)
	if err != nil {
		return out, err
	}
	mfaPersonas := []string{} // never NULL: ANY(NULL) is NULL, not false
	for _, p := range s.groupSchemaOrDefault().Personas() {
		if s.ownersNeedMFA(p) {
			mfaPersonas = append(mfaPersonas, p.String())
		}
	}
	limit := q.Page.PageLimit()
	rows, err := s.q.PermissionGroupsPage(ctx, db.PermissionGroupsPageParams{
		Persona: persona.String(), IncludeDeleted: q.IncludeDeleted, Ownerless: q.Ownerless,
		After: after[0], MfaPersonas: mfaPersonas, PageLimit: int64(limit + 1),
	})
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		out.Items = append(out.Items, publicGroup(r))
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.Next = pageCursor(out.Items[limit-1].ID)
	}
	return out, nil
}

// ListGroupMembers lists the subjects holding a role in a live group, ordered
// by subject kind, then id.
func (s *Engine) ListGroupMembers(ctx context.Context, ref iam.GroupRef, q iam.MemberQuery) (iam.ListPage[iam.GroupMember], error) {
	var out iam.ListPage[iam.GroupMember]
	if err := s.requirePG(); err != nil {
		return out, err
	}
	g, err := s.resolveGroup(ctx, s.groupStore(), ref)
	if err != nil {
		return out, err
	}
	after, err := cursor.Keys(q.Page.Cursor, 2)
	if err != nil {
		return out, err
	}
	kinds := make([]string, 0, len(q.Kinds))
	for _, k := range q.Kinds {
		kinds = append(kinds, string(k))
	}
	roles := make([]string, 0, len(q.Roles))
	for _, r := range q.Roles {
		if r.Persona() == g.Persona {
			roles = append(roles, r.String())
		}
	}
	if len(q.Roles) > 0 && len(roles) == 0 {
		return out, nil // no role of this group's persona: nobody holds one
	}
	limit := q.Page.PageLimit()
	rows, err := s.q.GroupMembersPage(ctx, db.GroupMembersPageParams{
		GroupID: g.ID, Kinds: kinds, Roles: roles, AfterKind: after[0], AfterID: after[1],
		LiveOnly: q.LiveOnly, PageLimit: int64(limit + 1),
	})
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		out.Items = append(out.Items, iam.GroupMember{
			Subject: iam.Subject{Kind: iam.SubjectKind(r.Kind), ID: r.ID}, Role: ident.RoleText(r.Role),
		})
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1]
		out.Next = pageCursor(string(last.Subject.Kind), last.Subject.ID)
	}
	if q.WithUsers {
		var ids []string
		for _, m := range out.Items {
			if m.Subject.Kind == iam.SubjectKindUser {
				ids = append(ids, m.Subject.ID)
			}
		}
		users, err := s.PublicUsers(ctx, ids)
		if err != nil {
			return out, err
		}
		for i, m := range out.Items {
			if u, ok := users[m.Subject.ID]; ok && m.Subject.Kind == iam.SubjectKindUser {
				out.Items[i].User = &u
			}
		}
	}
	return out, nil
}

// ListMemberships lists the live groups a subject holds a role in, ordered
// by persona, then id.
func (s *Engine) ListMemberships(ctx context.Context, subject iam.Subject, p iam.PageRequest) (iam.ListPage[iam.Membership], error) {
	var out iam.ListPage[iam.Membership]
	if err := s.requirePG(); err != nil {
		return out, err
	}
	subject.ID = strings.TrimSpace(subject.ID)
	if validSubject(subject) != nil {
		return out, nil
	}
	after, err := cursor.Keys(p.Cursor, 2)
	if err != nil {
		return out, err
	}
	limit := p.PageLimit()
	arg := db.GroupsOfUserPageParams{SubjectID: subject.ID, AfterPersona: after[0], AfterID: after[1], PageLimit: int64(limit + 1)}
	var rows []db.GroupsOfUserPageRow
	if subject.Kind == iam.SubjectKindUser {
		rows, err = s.q.GroupsOfUserPage(ctx, arg)
	} else {
		var apps []db.GroupsOfApplicationPageRow
		apps, err = s.q.GroupsOfApplicationPage(ctx, db.GroupsOfApplicationPageParams(arg))
		for _, r := range apps {
			rows = append(rows, db.GroupsOfUserPageRow(r))
		}
	}
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		g := publicGroup(r.PermissionGroup)
		out.Items = append(out.Items, iam.Membership{Group: g, Role: ident.RoleText(r.Role)})
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1].Group
		out.Next = pageCursor(last.Persona.String(), last.ID)
	}
	return out, nil
}

// pageCursor makes the opaque keyset cursor after the row with these keys.
func pageCursor(keys ...string) string { return cursor.Encode(keys) }
