package engine

// Group reads.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
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

// Groups reads many groups by id in one query, soft-deleted ones included.
// Unknown ids are absent. At most iam.MaxBatch distinct ids.
func (s *Engine) Groups(ctx context.Context, ids []string) (map[string]iam.Group, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	batch, err := groupBatch(ids)
	if err != nil {
		return nil, err
	}
	return s.groupStore().groupsByID(ctx, batch)
}

func groupBatch(groupIDs []string) ([]string, error) {
	ids := make([]string, 0, len(groupIDs))
	seen := make(map[string]bool, len(groupIDs))
	for _, id := range groupIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > iam.MaxBatch {
		return nil, fmt.Errorf("group batch has %d ids; at most %d", len(ids), iam.MaxBatch)
	}
	return ids, nil
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
	if _, ok := s.groupSchemaOrDefault().Persona(persona); !persona.IsZero() && (!ok || persona == iam.RootPersona) {
		return out, fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	after, err := decodePageCursor(q.Page.Cursor, 1)
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
	rows, err := s.pg.Query(ctx, `SELECT `+groupColumns+` FROM permission_groups g
 WHERE g.persona<>'root' AND ($1='' OR g.persona=$1) AND (($2 AND NOT $5) OR g.deleted_at IS NULL)
 AND ($3='' OR g.id>$3::uuid)
 AND (NOT $5 OR NOT `+usableOwner("g.id", "''", "NULL::uuid", "(g.persona=ANY($6::text[]))")+`)
 ORDER BY g.id LIMIT $4`, persona.String(), q.IncludeDeleted, after[0], limit+1, q.Ownerless, mfaPersonas)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, g)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.Next = encodePageCursor(out.Items[limit-1].ID)
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
	after, err := decodePageCursor(q.Page.Cursor, 2)
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
			roles = append(roles, r.Name())
		}
	}
	if len(q.Roles) > 0 && len(roles) == 0 {
		return out, nil // no role of this group's persona: nobody holds one
	}
	limit := q.Page.PageLimit()
	rows, err := s.pg.Query(ctx, `SELECT kind, id, role FROM (
 SELECT 'user' AS kind, r.user_id::text AS id, r.role, (u.deleted_at IS NULL AND COALESCE(u.metadata->'reserved','false'::jsonb)<>'true'::jsonb
   AND ((u.banned_at IS NULL AND u.banned_until IS NULL AND u.ban_reason IS NULL AND u.banned_by IS NULL) OR u.banned_until<=statement_timestamp())) AS live
  FROM group_user_roles r JOIN users u ON u.id=r.user_id WHERE r.permission_group_id=$1::uuid
 UNION ALL
 SELECT 'remote_application', r.remote_application_id::text, r.role, (a.enabled AND c.deleted_at IS NULL)
  FROM group_remote_application_roles r JOIN remote_applications a ON a.id=r.remote_application_id
  JOIN permission_groups c ON c.id=a.permission_group_id WHERE r.permission_group_id=$1::uuid) m
 WHERE (cardinality($2::text[])=0 OR kind=ANY($2::text[])) AND (cardinality($3::text[])=0 OR role=ANY($3::text[]))
 AND ($4='' OR (kind,id)>($4,$5)) AND (NOT $7 OR live)
 ORDER BY kind,id LIMIT $6`, g.ID, kinds, roles, after[0], after[1], limit+1, q.LiveOnly)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var m iam.GroupMember
		if err := rows.Scan(&m.Subject.Kind, &m.Subject.ID, scanRole(&m.Role, g.Persona)); err != nil {
			return out, err
		}
		out.Items = append(out.Items, m)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1]
		out.Next = encodePageCursor(string(last.Subject.Kind), last.Subject.ID)
	}
	if q.WithUsers {
		var ids []string
		for _, m := range out.Items {
			if m.Subject.Kind == iam.SubjectKindUser {
				ids = append(ids, m.Subject.ID)
			}
		}
		users, err := s.Users(ctx, ids)
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

// ListSubjectGroups lists the live groups a subject holds a role in, ordered
// by persona, then id.
func (s *Engine) ListSubjectGroups(ctx context.Context, subject iam.Subject, p iam.PageRequest) (iam.ListPage[iam.Membership], error) {
	var out iam.ListPage[iam.Membership]
	if err := s.requirePG(); err != nil {
		return out, err
	}
	subject.ID = strings.TrimSpace(subject.ID)
	if validSubject(subject) != nil {
		return out, nil
	}
	table, column, err := groupRoleTable(subject.Kind)
	if err != nil {
		return out, err
	}
	after, err := decodePageCursor(p.Cursor, 2)
	if err != nil {
		return out, err
	}
	limit := p.PageLimit()
	rows, err := s.pg.Query(ctx, fmt.Sprintf(`SELECT g.id::text, g.persona, g.created_at, g.deleted_at, a.role
 FROM %s a JOIN permission_groups g ON g.id=a.permission_group_id
 WHERE a.%s=$1::uuid AND g.deleted_at IS NULL
 AND ($2='' OR (g.persona,g.id)>($2,NULLIF($3,'')::uuid))
 ORDER BY g.persona,g.id LIMIT $4`, table, column), subject.ID, after[0], after[1], limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var m iam.Membership
		var role string
		if err := rows.Scan(&m.Group.ID, scanPersona(&m.Group.Persona), &m.Group.CreatedAt, &m.Group.DeletedAt, &role); err != nil {
			return out, err
		}
		m.Role = ident.Role(m.Group.Persona, role)
		out.Items = append(out.Items, m)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1].Group
		out.Next = encodePageCursor(last.Persona.String(), last.ID)
	}
	return out, nil
}

// encodePageCursor makes an opaque keyset cursor from the last row's sort key.
func encodePageCursor(key ...string) string {
	raw, _ := json.Marshal(key)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodePageCursor reads a cursor of n key parts; "" is the first page.
func decodePageCursor(cursor string, n int) ([]string, error) {
	if cursor == "" {
		return make([]string, n), nil
	}
	var key []string
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err == nil {
		err = json.Unmarshal(raw, &key)
	}
	if err != nil || len(key) != n || key[0] == "" {
		return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithCause(errors.New("invalid page cursor")))
	}
	return key, nil
}
