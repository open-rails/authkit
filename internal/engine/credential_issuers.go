package engine

// Rule CRED: a credential (API key, invite link, registration invite, and the
// roles of a group-registered application) records who issued it, and never
// outlives that issuer's authority. The issuer is a user, or the operator
// (NULL, never auto-revoked); machine actors cannot issue credentials. An
// application's issuer is its registrar, the user who supplied its keys.
// Three layers hold it:
//   - the sweep (revokeUncoveredCredentials) revokes what a creator no longer
//     covers after any authority change, including a changed role catalog at
//     boot (reconcileRoleCatalog);
//   - every use re-checks the creator is live (issuerLive, registrarLive), so
//     a banned or deleted creator's credentials fail even where no sweep ran;
//   - a purge deletes the creator's keys and links with the account.
// An API key or application can present no second factor, so neither ever
// holds a role that needs one, whoever issued it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/rbac"
)

// credentialIssuer is the creator a credential issued by a records: the user,
// or "" for the operator. Machine actors cannot issue credentials.
func credentialIssuer(a iam.Actor) (string, error) {
	switch a.Kind() {
	case iam.ActorOperator:
		return "", nil
	case iam.ActorUser:
		return a.ID(), nil
	}
	return "", iam.ErrInsufficientAuthority
}

// issuerLive is a SQL predicate: the issuer in column col is the operator
// (NULL) or an account that is not deleted, reserved or banned.
func issuerLive(col string) string {
	return `(` + col + ` IS NULL OR EXISTS(SELECT 1 FROM users issuer WHERE issuer.id=` + col + ` AND issuer.deleted_at IS NULL
 AND COALESCE(issuer.metadata->'reserved','false'::jsonb)<>'true'::jsonb
 AND ((issuer.banned_at IS NULL AND issuer.banned_until IS NULL AND issuer.ban_reason IS NULL AND issuer.banned_by IS NULL) OR issuer.banned_until<=statement_timestamp())))`
}

// registrarLive is a SQL predicate on the remote_applications alias app: a
// group registration confers authority only while its registrar is live.
// Operator and domain registrations have no registrar.
func registrarLive(app string) string {
	return `(` + app + `.trust_root<>'user' OR ` + app + `.registered_by IS NOT NULL AND ` + issuerLive(app+".registered_by") + `)`
}

// requireCredentialRevoke is the authority to take back a credential of role:
// CAP(capability) plus COVER(role). A role that no longer exists confers
// nothing, so it needs only CAP.
func (s *Engine) requireCredentialRevoke(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, capability iam.Perm, role iam.Role) error {
	auth, err := s.actorAuthority(ctx, st, a, g)
	if err != nil {
		return err
	}
	if err := auth.requireCap(capability); err != nil {
		return err
	}
	if err := s.requireRoleCover(ctx, st, auth, g, role); err != nil && !errors.Is(err, iam.ErrRoleNotAssignable) {
		return err
	}
	return nil
}

// reconcileRoleCatalog runs at New under the authority lock. A catalog role
// that shadows a custom role stored in a live group refuses the boot: it would
// silently re-point every holder, key and link of that custom role. When the
// catalog differs from the one last reconciled, the whole-site sweep re-checks
// every live credential against its creator under the new catalog. That sweep
// never refuses the boot: it retires what the new catalog no longer allows and
// logs what it did.
func (s *Engine) reconcileRoleCatalog(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	sch := s.groupSchemaOrDefault()
	fingerprint := s.roleCatalogFingerprint()
	return s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		st.reconcile = true
		if err := refuseShadowedCustomRoles(ctx, st, sch); err != nil {
			return err
		}
		var stored string
		err := st.q.QueryRow(ctx, `SELECT fingerprint FROM role_catalog_state`).Scan(&stored)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if stored == fingerprint {
			return nil
		}
		rootID, err := s.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		st.touched = append(st.touched, authorityTouch{groupID: rootID})
		_, err = st.q.Exec(ctx, `INSERT INTO role_catalog_state(fingerprint) VALUES($1)
 ON CONFLICT (singleton) DO UPDATE SET fingerprint=EXCLUDED.fingerprint, swept_at=now()`, fingerprint)
		return err
	})
}

func refuseShadowedCustomRoles(ctx context.Context, st *permissionGroupStore, sch *rbac.Schema) error {
	rows, err := st.q.Query(ctx, `SELECT DISTINCT g.persona, r.role FROM group_custom_roles r
 JOIN permission_groups g ON g.id=r.permission_group_id WHERE g.deleted_at IS NULL ORDER BY 1, 2`)
	if err != nil {
		return err
	}
	var shadowed []string
	for rows.Next() {
		var persona iam.Persona
		var role iam.Role
		if err := rows.Scan(&persona, &role); err != nil {
			rows.Close()
			return err
		}
		if _, ok := sch.Role(persona, role); ok {
			shadowed = append(shadowed, fmt.Sprintf("%s/%s", persona, role))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(shadowed) > 0 {
		return fmt.Errorf("authkit: catalog roles %s shadow custom roles stored in live groups; rename the catalog roles, or delete those custom roles first", strings.Join(shadowed, ", "))
	}
	return nil
}

// roleCatalogFingerprint identifies everything the credential sweep reads from
// the configuration: each persona's custom-role switch, every role's grants,
// and which permissions need MFA (no key or application holds one of those
// once 2FA is on).
func (s *Engine) roleCatalogFingerprint() string {
	sch := s.groupSchemaOrDefault()
	h := sha256.New()
	fmt.Fprintf(h, "twofactor=%t\n", s.TwoFactorEnabled())
	for _, p := range sch.MFAPermissions() {
		fmt.Fprintf(h, "mfa %s\n", p)
	}
	for _, name := range sch.Personas() {
		p, _ := sch.Persona(name)
		fmt.Fprintf(h, "persona %s custom=%t\n", name, p.CustomRoles)
		roles := slices.Clone(p.Roles)
		slices.SortFunc(roles, func(a, b rbac.Role) int { return strings.Compare(string(a.Name), string(b.Name)) })
		for _, r := range roles {
			fmt.Fprintf(h, "role %s %s\n", r.Name, strings.Join(slices.Sorted(slices.Values(r.Permissions)), ","))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// idCursor reads a keyset cursor: the id of the previous page's last item.
// Credential ids are uuidv7, so id order is creation order.
func idCursor(p iam.PageRequest) (*string, error) {
	c := strings.TrimSpace(p.Cursor)
	if c == "" {
		return nil, nil
	}
	if !isUUID(c) {
		return nil, errmodel.E(errmodel.CodeInvalidRequest)
	}
	return &c, nil
}

// idPage cuts rows fetched with LIMIT limit+1 to one page.
func idPage[T any](rows []T, limit int, id func(T) string) iam.ListPage[T] {
	page := iam.ListPage[T]{Items: rows}
	if len(rows) > limit {
		page.Items = rows[:limit]
		page.Next = id(rows[limit-1])
	}
	if page.Items == nil {
		page.Items = []T{}
	}
	return page
}
