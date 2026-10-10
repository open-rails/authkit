package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/netguard"
)

// trustSourcePolicy relaxes remote-application trust-source validation.
// AllowPrivateNetworkJWKS admits loopback/private-network JWKS URLs (local
// development only; production leaves it off, see Config.Token.AllowPrivateNetworkJWKS).
type trustSourcePolicy struct {
	AllowPrivateNetworkJWKS bool
}

func (s *Engine) trustSourcePolicy() trustSourcePolicy {
	return trustSourcePolicy{AllowPrivateNetworkJWKS: s.cfg.Token.AllowPrivateNetworkJWKS}
}

// normalizeRemoteAppTrustSource validates the mutually-exclusive trust source
// of a registration and returns the normalized mode. Empty mode is inferred: a
// key list means static, otherwise jwks. It is the single validation gate so
// the XOR rule cannot be bypassed.
func normalizeRemoteAppTrustSource(jwksURI string, mode iam.RemoteApplicationMode, keys []iam.RemoteApplicationKey, policy trustSourcePolicy) (iam.RemoteApplicationMode, error) {
	allowInsecureJWKS := policy.AllowPrivateNetworkJWKS
	mode = iam.RemoteApplicationMode(strings.ToLower(strings.TrimSpace(string(mode))))
	jwksURI = strings.TrimSpace(jwksURI)
	if mode == "" {
		if len(keys) > 0 {
			mode = iam.RemoteApplicationModeStatic
		} else {
			mode = iam.RemoteApplicationModeJWKS
		}
	}
	switch mode {
	case iam.RemoteApplicationModeJWKS:
		// No jwks_uri: a resource server discovers it from the issuer's
		// metadata (RFC 8414).
		if len(keys) > 0 {
			return "", fmt.Errorf("%w: jwks_uri and public_keys are mutually exclusive — register one trust source, never both", iam.ErrInvalidRemoteApplication)
		}
		if jwksURI == "" {
			break
		}
		if err := validateJWKSURI(jwksURI, allowInsecureJWKS); err != nil {
			return "", fmt.Errorf("%w: %v", iam.ErrInvalidRemoteApplication, err)
		}
	case iam.RemoteApplicationModeStatic:
		if len(keys) == 0 {
			return "", fmt.Errorf("%w: static mode requires a non-empty public_keys list", iam.ErrInvalidRemoteApplication)
		}
		if jwksURI != "" {
			return "", fmt.Errorf("%w: jwks_uri and public_keys are mutually exclusive — register one trust source, never both", iam.ErrInvalidRemoteApplication)
		}
		for i, k := range keys {
			if _, _, err := jose.StaticKey(k); err != nil {
				return "", fmt.Errorf("%w: public_keys[%d]: %v", iam.ErrInvalidRemoteApplication, i, err)
			}
		}
	default:
		return "", fmt.Errorf("%w: unknown mode %q (want jwks|static)", iam.ErrInvalidRemoteApplication, mode)
	}
	return mode, nil
}

// validateJWKSURI rejects jwks_uri values that are:
//   - not HTTPS
//   - pointing at localhost or well-known internal hostnames
//   - using a literal private/reserved IP address
//
// This is a syntactic check (no DNS resolution). The verifier's SSRF-guarding
// dialer provides a second layer against DNS rebinding at fetch time.
//
// allowInsecure (Token.AllowPrivateNetworkJWKS) permits http and
// loopback/private hosts for local federation; still requires a parseable
// http(s) URL with a host.
func validateJWKSURI(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("jwks_uri is not a valid URL: %v", err)
	}
	if allowInsecure {
		if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("jwks_uri must use http or https, got %q", u.Scheme)
		}
		if u.Hostname() == "" {
			return errors.New("jwks_uri must have a non-empty host")
		}
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("jwks_uri must use https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("jwks_uri must have a non-empty host")
	}
	if netguard.IsInternalHostname(host) {
		return fmt.Errorf("jwks_uri host %q is not a public address", host)
	}
	if ip := net.ParseIP(host); ip != nil && netguard.IsPrivateIP(ip) {
		return fmt.Errorf("jwks_uri %q resolves to a private/reserved IP — not allowed", host)
	}
	return nil
}

func decodeRemoteAppKeys(raw []byte) []iam.RemoteApplicationKey {
	if len(raw) == 0 {
		return nil
	}
	var keys []iam.RemoteApplicationKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil
	}
	return keys
}

// decodeRoleMap reads a stored role_map: role name → role text.
func decodeRoleMap(raw []byte) map[string]iam.Role {
	if len(raw) == 0 {
		return nil
	}
	var texts map[string]string
	if json.Unmarshal(raw, &texts) != nil || len(texts) == 0 {
		return nil
	}
	out := make(map[string]iam.Role, len(texts))
	for name, role := range texts {
		out[name] = ident.RoleText(role)
	}
	return out
}

// encodeRoleMap is m as stored; nil maps none.
func encodeRoleMap(m map[string]iam.Role) []byte {
	if len(m) == 0 {
		return nil
	}
	texts := make(map[string]string, len(m))
	for name, role := range m {
		texts[name] = role.String()
	}
	b, _ := json.Marshal(texts)
	return b
}

// validRoleMap refuses a role_map naming an empty role name or a role that
// is not one of the group persona's.
func (s *Engine) validRoleMap(persona iam.Persona, m map[string]iam.Role) error {
	for name, role := range m {
		if strings.TrimSpace(name) == "" || name != strings.TrimSpace(name) {
			return fmt.Errorf("%w: role_map has an empty or padded role name", iam.ErrInvalidRemoteApplication)
		}
		if !s.validRoleForPersona(s.groupSchemaOrDefault(), persona, role) {
			return fmt.Errorf("role_map %q: %q is not a role of a %q group: %w", name, role, persona, iam.ErrRoleNotAssignable)
		}
	}
	return nil
}

func remoteAppFromRow(row db.RemoteApplication) *iam.RemoteApplication {
	ra := &iam.RemoteApplication{
		ID: row.ID, GroupID: row.PermissionGroupID,
		Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: iam.RemoteApplicationMode(row.Mode),
		PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Enabled: row.Enabled,
		TrustRoot: iam.ApplicationTrustRoot(row.TrustRoot),
		RoleMap:   decodeRoleMap(row.RoleMap),
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	return ra
}

// upsertRemoteApplication writes in under the authority transaction st, keyed
// by issuer, in the group in.GroupID. A set TrustRoot is stored;
// unset, a new row is manual and an existing one keeps its own. Callers
// authorize.
func (s *Engine) upsertRemoteApplication(ctx context.Context, st *permissionGroupStore, in iam.RemoteApplication) (*iam.RemoteApplication, error) {
	q := db.New(st.q)
	issuer := strings.TrimSpace(in.Issuer)
	jwksURI := strings.TrimSpace(in.JWKSURI)
	if issuer == "" {
		return nil, iam.ErrInvalidRemoteApplication
	}
	if !ident.ValidIssuer(issuer) {
		return nil, fmt.Errorf("%w: issuer must be an absolute http(s) URL of at most %d bytes", iam.ErrInvalidRemoteApplication, ident.MaxIssuerLen)
	}
	// AK-AUTH-01: a remote_application must never claim the platform's own
	// issuer or a provider's. The verifier keys issuers by string and upserts by issuer, so a
	// federated registration under the platform issuer would overwrite the
	// trusted local entry, swapping the platform's signing keys and breaking
	// verification of all first-party tokens. This guards every caller,
	// including bootstrap.
	if s.reservedIssuer(issuer) {
		return nil, iam.ErrReservedIssuer
	}
	mode, err := normalizeRemoteAppTrustSource(jwksURI, in.Mode, in.PublicKeys, s.trustSourcePolicy())
	if err != nil {
		return nil, err
	}
	var keysJSON []byte
	if mode == iam.RemoteApplicationModeStatic {
		keysJSON, err = json.Marshal(in.PublicKeys)
		if err != nil {
			return nil, iam.ErrInvalidRemoteApplication
		}
	}
	// Remote applications are group-nested: every issuer maps to one controlling
	// permission group.
	t := strings.TrimSpace(in.GroupID)
	if t == "" {
		return nil, fmt.Errorf("%w: group_id is required (remote applications are group-nested)", iam.ErrInvalidRemoteApplication)
	}
	if err := lockPermissionGroup(ctx, st.q, t); err != nil {
		return nil, err
	}
	existing, err := q.RemoteApplicationByIssuer(ctx, issuer)
	if err == nil && existing.PermissionGroupID != t {
		return nil, iam.ErrRemoteApplicationIssuerConflict
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("look up remote application issuer: %w", err)
	}

	if err == nil && existing.Enabled && !in.Enabled {
		// q is transaction-bound both here and during bootstrap reconciliation.
		if err := s.refuseSubjectOwnerLoss(ctx, st, iam.RemoteApplicationSubject(existing.ID)); err != nil {
			return nil, err
		}
	}
	row, err := q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{
		PermissionGroupID: t,
		Issuer:            issuer,
		JwksUri:           jwksURI,
		Mode:              string(mode),
		PublicKeys:        keysJSON,
		Enabled:           in.Enabled,
		CatalogIssuer:     s.cfg.Token.Issuer,
		RoleMap:           encodeRoleMap(in.RoleMap),
	})
	// The atomic upsert guard also covers an issuer claimed after our lookup.
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrRemoteApplicationIssuerConflict
	}
	if err != nil {
		return nil, err
	}
	out := remoteAppFromRow(row)
	if in.TrustRoot != "" && in.TrustRoot != out.TrustRoot {
		out.TrustRoot = in.TrustRoot
		if err := q.RemoteApplicationSetTrustRoot(ctx, db.RemoteApplicationSetTrustRootParams{ID: out.ID, TrustRoot: string(out.TrustRoot)}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// reservedIssuer reports whether issuer names this deployment's own accounts or
// one of its identity providers; no remote application may claim it. Matching
// ignores case and a trailing slash, so trivial spellings cannot bypass it.
func (s *Engine) reservedIssuer(issuer string) bool {
	key := issuerKey(issuer)
	if key == "" {
		return false
	}
	if issuerKey(s.cfg.Token.Issuer) == key {
		return true
	}
	for _, p := range s.providers {
		if p != nil && issuerKey(p.Issuer()) == key {
			return true
		}
	}
	return false
}

// accountPeerIssuer reports whether issuer is another deployment sharing this
// account store. A peer's tokens name accounts here, so only the system may
// register it as a remote application; a group registration under it would
// sign for every shared account.
func (s *Engine) accountPeerIssuer(issuer string) bool {
	key := issuerKey(issuer)
	for _, peer := range s.cfg.Token.AccountIssuers {
		if key != "" && issuerKey(peer) == key {
			return true
		}
	}
	return false
}

func issuerKey(issuer string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(issuer), "/"))
}

// GetRemoteApplication returns a remote_application by OIDC issuer URL.
func (s *Engine) GetRemoteApplication(ctx context.Context, issuer string) (*iam.RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, iam.ErrInvalidRemoteApplication
	}
	row, err := s.q.RemoteApplicationByIssuer(ctx, issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		return nil, err
	}
	// Issuer lookups are verification-facing: a disabled application must fail
	// closed on the next request, not at the next reconcile (#323). Admin reads
	// use RemoteApplication / ListRemoteApplications.
	if !row.Enabled {
		return nil, iam.ErrRemoteApplicationNotFound
	}
	group, err := s.groupStore().groupByID(ctx, row.PermissionGroupID)
	if err != nil {
		return nil, err
	}
	if group.DeletedAt != nil {
		return nil, iam.ErrRemoteApplicationNotFound
	}
	return remoteAppFromRow(row), nil
}

// RemoteApplication is the management read of an application, by id or by
// issuer, disabled or in a retired group included, with its role and the
// permissions it confers now.
func (s *Engine) RemoteApplication(ctx context.Context, ref iam.AppRef) (iam.RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return iam.RemoteApplication{}, err
	}
	var row db.RemoteApplication
	var err error
	switch {
	case ref.ID() != "":
		if !isUUID(ref.ID()) {
			return iam.RemoteApplication{}, iam.ErrRemoteApplicationNotFound
		}
		row, err = s.q.RemoteApplicationByID(ctx, ref.ID())
	case ref.Issuer() != "":
		row, err = s.q.RemoteApplicationByIssuer(ctx, ref.Issuer())
	default:
		return iam.RemoteApplication{}, iam.ErrRemoteApplicationNotFound
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.RemoteApplication{}, iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		return iam.RemoteApplication{}, err
	}
	apps := []iam.RemoteApplication{*remoteAppFromRow(row)}
	if err := s.loadApplicationRoles(ctx, s.pg, row.PermissionGroupID, apps); err != nil {
		return iam.RemoteApplication{}, err
	}
	return apps[0], nil
}

// loadApplicationRoles fills the Role and Permissions of apps, all controlled
// by groupID. An application confers nothing while it is disabled or its
// group is deleted, and never a role that needs MFA.
func (s *Engine) loadApplicationRoles(ctx context.Context, q db.DBTX, groupID string, apps []iam.RemoteApplication) error {
	if len(apps) == 0 {
		return nil
	}
	ids := make([]string, len(apps))
	for i, a := range apps {
		ids[i] = a.ID
	}
	queries := db.New(q)
	group, err := queries.AuthorityGroupState(ctx, groupID)
	if err != nil {
		return err
	}
	rows, err := queries.GroupRolesForSubjects(ctx, db.GroupRolesForSubjectsParams{GroupID: groupID, UserIds: []string{}, ApplicationIds: ids})
	if err != nil {
		return err
	}
	roles := make(map[string]iam.Role, len(rows))
	for _, r := range rows {
		roles[r.SubjectID] = ident.RoleText(r.Role)
	}
	for i := range apps {
		apps[i].Role = roles[apps[i].ID]
		apps[i].Permissions = []iam.Perm{}
		if !apps[i].Enabled || group.DeletedAt != nil || apps[i].Role.IsZero() {
			continue
		}
		if s.TwoFactorEnabled() && s.roleRequiresMFA(apps[i].Role.Persona(), apps[i].Role) {
			continue
		}
		grants, _ := s.roleGrants(apps[i].Role.Persona(), apps[i].Role)
		apps[i].Permissions = ident.Perms(grants)
	}
	return nil
}
