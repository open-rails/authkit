package engine

// Group reads and deletion.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Group reads one group. A slug resolves only a live group (a former slug
// forwards to its group); an id also returns a soft-deleted group, with
// DeletedAt set. Absence is ErrGroupNotFound.
func (s *Engine) Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error) {
	if err := s.requirePG(); err != nil {
		return iam.Group{}, err
	}
	st := s.groupStore()
	id := ref.ID()
	if id == "" {
		if err := iam.ValidateGroupInstanceSlug(ref); err != nil {
			return iam.Group{}, iam.ErrGroupNotFound
		}
		g, err := s.resolveGroup(ctx, st, ref)
		if err != nil {
			return iam.Group{}, err
		}
		id = g.ID
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

// ListGroups lists groups by slug, then id. The root group is never listed.
func (s *Engine) ListGroups(ctx context.Context, q iam.GroupQuery) (iam.ListPage[iam.Group], error) {
	var out iam.ListPage[iam.Group]
	if err := s.requirePG(); err != nil {
		return out, err
	}
	persona := iam.Persona(strings.TrimSpace(string(q.Persona)))
	if _, ok := s.groupSchemaOrDefault().Persona(persona); persona != "" && (!ok || persona == iam.RootPersona) {
		return out, fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	after, err := decodePageCursor(q.Page.Cursor, 2)
	if err != nil {
		return out, err
	}
	limit := q.Page.PageLimit()
	rows, err := s.pg.Query(ctx, `SELECT `+groupColumns+` FROM permission_groups
 WHERE persona<>'root' AND instance_slug IS NOT NULL AND ($1='' OR persona=$1) AND ($2 OR deleted_at IS NULL)
 AND ($3='' OR strpos(instance_slug,$3)>0 OR strpos(lower(COALESCE(display_name,'')),$3)>0)
 AND ($4='' OR (instance_slug,id)>($4,NULLIF($5,'')::uuid))
 ORDER BY instance_slug,id LIMIT $6`, persona, q.IncludeDeleted, strings.ToLower(strings.TrimSpace(q.Search)), after[0], after[1], limit+1)
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
		last := out.Items[limit-1]
		out.Next = encodePageCursor(last.Slug, last.ID)
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
		roles = append(roles, strings.TrimSpace(string(r)))
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
		if err := rows.Scan(&m.Subject.Kind, &m.Subject.ID, &m.Role); err != nil {
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
// by persona, slug, then id.
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
	after, err := decodePageCursor(p.Cursor, 3)
	if err != nil {
		return out, err
	}
	limit := p.PageLimit()
	rows, err := s.pg.Query(ctx, fmt.Sprintf(`SELECT g.id::text, g.persona, COALESCE(g.instance_slug,''), COALESCE(g.display_name,''), g.deleted_at, a.role
 FROM %s a JOIN permission_groups g ON g.id=a.permission_group_id
 WHERE a.%s=$1::uuid AND g.deleted_at IS NULL
 AND ($2='' OR (g.persona,COALESCE(g.instance_slug,''),g.id)>($2,$3,NULLIF($4,'')::uuid))
 ORDER BY g.persona,COALESCE(g.instance_slug,''),g.id LIMIT $5`, table, column), subject.ID, after[0], after[1], after[2], limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var m iam.Membership
		if err := rows.Scan(&m.Group.ID, &m.Group.Persona, &m.Group.Slug, &m.Group.DisplayName, &m.Group.DeletedAt, &m.Role); err != nil {
			return out, err
		}
		out.Items = append(out.Items, m)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1].Group
		out.Next = encodePageCursor(string(last.Persona), last.Slug, last.ID)
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

// DeleteGroup soft-deletes a group: it stops resolving and granting, while its
// rows and name reservations stay. It needs <persona>:self:delete. The root
// group cannot be deleted. An operator deleting an already deleted group by
// id gets it back unchanged.
func (s *Engine) DeleteGroup(ctx context.Context, a iam.Actor, ref iam.GroupRef) (iam.Group, error) {
	var out iam.Group
	if err := requireActor(a); err != nil {
		return out, err
	}
	err := s.withGroupMutation(ctx, ref, func(st *permissionGroupStore, g groupTarget) error {
		auth, err := s.actorAuthority(ctx, st, a, g)
		if err != nil {
			return err
		}
		if g.Persona == iam.RootPersona {
			return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
		}
		if err := auth.requireCap(iam.PermSelfDelete(g.Persona)); err != nil {
			return err
		}
		surviving, err := outsideApplicationOwnerGroups(ctx, st, g.ID)
		if err != nil {
			return err
		}
		if _, err = st.q.Exec(ctx, `UPDATE permission_groups SET deleted_at=$2,updated_at=$2 WHERE id=$1::uuid`, g.ID, st.now()); err != nil {
			return err
		}
		for _, id := range surviving {
			if err := s.requireRemainingOwner(ctx, st, id, iam.Subject{}); err != nil {
				return err
			}
		}
		out, err = st.groupByID(ctx, g.ID)
		return err
	})
	if errors.Is(err, iam.ErrGroupNotFound) && a.Kind() == iam.ActorOperator && ref.ID() != "" {
		if g, gerr := s.Group(ctx, ref); gerr == nil && g.DeletedAt != nil {
			return g, nil
		}
	}
	return out, err
}

// PurgeGroup permanently deletes a group, live or soft-deleted, with every
// role, custom role, key and link in it. Only an operator may purge. Purging
// an unknown group is a no-op.
func (s *Engine) PurgeGroup(ctx context.Context, a iam.Actor, ref iam.GroupRef, opts iam.PurgeGroupOptions) error {
	if err := requireActor(a); err != nil {
		return err
	}
	if a.Kind() != iam.ActorOperator {
		return iam.ErrInsufficientRoleAuthority
	}
	err := s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		id := ref.ID()
		if id == "" {
			g, err := s.resolveGroup(ctx, st, ref)
			if err != nil {
				return err
			}
			id = g.ID
		} else if !isUUID(id) {
			return iam.ErrGroupNotFound
		}
		return s.deleteGroupTx(ctx, st, strings.ToLower(id), opts)
	})
	if errors.Is(err, iam.ErrGroupNotFound) {
		return nil
	}
	return err
}

// MemberUserIDByEmail returns the account an email may add to a group: its
// email is verified and it is neither deleted nor reserved. Any other holder
// is ok=false, so an unproven or retired account never receives a role by
// email; the caller invites the address instead.
func (s *Engine) MemberUserIDByEmail(ctx context.Context, email string) (string, bool, error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	var id string
	err := s.pg.QueryRow(ctx, `SELECT id::text FROM users WHERE email=lower($1::text)::public.citext AND email_verified
 AND deleted_at IS NULL AND COALESCE(metadata->'reserved','false'::jsonb)<>'true'::jsonb`, email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}
