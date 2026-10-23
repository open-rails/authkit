package engine

// Delegated invitations and group-registered applications never outlive their
// issuer's authority. Organization API keys instead hold their own group role;
// their creator is audit metadata. Personal tokens use the owner's live grants.
// Machine identities cannot create any of these credentials. An application's
// issuer is its registrar, the user who supplied its keys.
// Apps sharing an account store (Token.AccountIssuers) share membership but
// not role catalogs: a credential also records the app it was issued through
// (catalog_issuer), and only that app judges it, under its own catalog.
// Three layers hold it:
//   - the sweep (revokeUncoveredCredentials) revokes what a creator no longer
//     covers after any authority change, including a changed role catalog at
//     boot (reconcileRoleCatalog); a change made through one app has every
//     other account issuer sweep its own (credential_sweeps.go);
//   - invitation and application use re-check current issuer capability and
//     role coverage; personal tokens intersect the owner's live grants;
//   - a purge deletes personal credentials and clears organization-key audit
//     references without revoking the group's keys.
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

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cursor"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/rbac"
)

// credentialIssuer is the creator a credential issued by a records: the user,
// or "" for the system. Machine identities cannot issue credentials.
func credentialIssuer(a auth.Identity) (string, error) {
	switch cs := stateOf(a); {
	case cs.IsSystem():
		return "", nil
	case cs.IsUser():
		return cs.ID(), nil
	}
	return "", iam.ErrInsufficientAuthority
}

// requireCredentialRevoke is the authority to take back a credential of role:
// CAP(capability) plus COVER(role), which a removed role does not need.
func (s *Engine) requireCredentialRevoke(ctx context.Context, st *permissionGroupStore, a auth.Identity, g groupTarget, capability iam.Perm, role iam.Role) error {
	auth, err := s.identityAuthority(ctx, st, a, g)
	if err != nil {
		return err
	}
	if err := auth.requireCap(capability); err != nil {
		return err
	}
	return s.requireHeldRoleCover(ctx, st, auth, g, role)
}

// reconcileRoleCatalog runs at New under the authority lock. When this app's
// catalog differs from the one it last reconciled, the whole-site sweep
// re-checks every live credential this app judges against its creator under
// the new catalog. That sweep never refuses the boot: it retires what the new
// catalog no longer allows and logs what it did. Other apps' catalogs are
// theirs: they never cause a sweep here.
func (s *Engine) reconcileRoleCatalog(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	fingerprint := s.roleCatalogFingerprint()
	return s.withAuthorityMutation(ctx, auth.Identity{}, func(st *permissionGroupStore) error {
		st.reconcile = true
		q := db.New(st.q)
		stored, err := q.RoleCatalogFingerprint(ctx, s.cfg.Token.Issuer)
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
		return q.RoleCatalogSet(ctx, db.RoleCatalogSetParams{Issuer: s.cfg.Token.Issuer, Fingerprint: fingerprint, Roles: s.declaredRoles()})
	})
}

// declaredRoles is every persona:role name the catalog declares.
func (s *Engine) declaredRoles() []string {
	sch := s.groupSchemaOrDefault()
	out := []string{}
	for _, name := range sch.Personas() {
		p, _ := sch.Persona(name)
		for _, r := range p.Roles {
			out = append(out, catalogRoleName(name.String(), r.Name.Name()))
		}
	}
	return out
}

func catalogRoleName(persona, role string) string { return persona + ":" + role }

// roleCatalogFingerprint identifies everything the credential sweep reads from
// the configuration: every role's grants, which personas define custom roles,
// and which permissions need MFA (no key or application holds one of those
// once 2FA is on).
func (s *Engine) roleCatalogFingerprint() string {
	sch := s.groupSchemaOrDefault()
	h := sha256.New()
	fmt.Fprintf(h, "mfa-policy=2 mode=%s passkeys=%t\n", s.cfg.TwoFactor.Mode, s.PasskeysEnabled())
	for _, method := range []iam.TwoFactorMethod{iam.TwoFactorTOTP, iam.TwoFactorSMS} {
		fmt.Fprintf(h, "factor %s=%t\n", method, s.twoFactorMethodConfigured(method))
	}
	for _, p := range sch.MFAPermissions() {
		fmt.Fprintf(h, "mfa %s\n", p)
	}
	for _, name := range sch.Personas() {
		p, _ := sch.Persona(name)
		fmt.Fprintf(h, "persona %s\n", name)
		if p.CustomRoles {
			fmt.Fprintf(h, "custom roles\n")
		}
		roles := slices.Clone(p.Roles)
		slices.SortFunc(roles, func(a, b rbac.Role) int { return strings.Compare(a.Name.Name(), b.Name.Name()) })
		for _, r := range roles {
			fmt.Fprintf(h, "role %s %s\n", r.Name.Name(), strings.Join(slices.Sorted(slices.Values(r.Permissions)), ","))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// idCursor reads a keyset cursor: the id of the previous page's last item.
// Credential ids are uuidv7, so id order is creation order.
func idCursor(p iam.PageRequest) (*string, error) {
	keys, err := cursor.Keys(strings.TrimSpace(p.Cursor), 1)
	if err != nil || keys[0] == "" {
		return nil, err
	}
	if !isUUID(keys[0]) {
		return nil, cursor.Invalid()
	}
	return &keys[0], nil
}

// idPage cuts rows fetched with LIMIT limit+1 to one page.
func idPage[T any](rows []T, limit int, id func(T) string) iam.ListPage[T] {
	page := iam.ListPage[T]{Items: rows}
	if len(rows) > limit {
		page.Items = rows[:limit]
		page.Next = pageCursor(id(rows[limit-1]))
	}
	if page.Items == nil {
		page.Items = []T{}
	}
	return page
}
