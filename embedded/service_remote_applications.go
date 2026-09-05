package embedded

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/netguard"
)

func validateRemoteAppSlug(slug string) error {
	if !validSlug(slug) {
		return ErrInvalidRemoteApplication
	}
	return nil
}

var (
	// ErrRemoteApplicationIssuerConflict indicates the issuer belongs to another group.
	ErrRemoteApplicationIssuerConflict = authkit.ErrRemoteApplicationIssuerConflict
	// ErrRemoteApplicationNotFound indicates no remote_application matched.
	ErrRemoteApplicationNotFound = authkit.ErrRemoteApplicationNotFound
	// ErrInvalidRemoteApplication is defined in authkit and re-exported here.
	ErrInvalidRemoteApplication = authkit.ErrInvalidRemoteApplication
	// ErrReservedIssuer indicates an attempt to register a remote_application
	// under the platform's own issuer string. The platform issuer is the local,
	// first-party signing identity; allowing a federated remote_application to
	// claim it would overwrite the trusted local issuer entry (key-swap / auth
	// DoS — see AK-AUTH-01).
	ErrReservedIssuer = authkit.ErrReservedIssuer
)

// Remote-application trust modes (#74). A remote_application is a federation
// PRINCIPAL whose credential is a key, with exactly one trust source:
//
//	jwks   — keys fetched + refreshed from JWKSURI; rotation is publishing a new
//	         kid at the same URL.
//	static — authorized_keys-style human-managed PEM list for principals without
//	         a JWKS endpoint; manual rotation by design.
//
// Remote-application trust modes are defined in authkit (core-free) and
// re-exported here.
const (
	RemoteAppModeJWKS   = authkit.RemoteAppModeJWKS
	RemoteAppModeStatic = authkit.RemoteAppModeStatic
)

// RemoteAppKey is defined in authkit (core-free) and re-exported here.
type RemoteAppKey = authkit.RemoteAppKey

// NormalizeRemoteAppTrustSource validates the mutually-exclusive trust source of
// a registration and returns the normalized mode. Empty mode is inferred: a key
// list means static, otherwise jwks. It is the single validation gate so the XOR
// rule cannot be bypassed. allowInsecureJWKS relaxes the https/private-address
// jwks_uri checks (Applications.AllowPrivateNetworkJWKS; local federation only).
// TrustSourcePolicy relaxes remote-application trust-source validation.
// AllowPrivateNetworkJWKS admits loopback/private-network JWKS URLs (local
// development only; production leaves it off, see Config.Applications).
type TrustSourcePolicy struct {
	AllowPrivateNetworkJWKS bool
}

func (s *Service) trustSourcePolicy() TrustSourcePolicy {
	return TrustSourcePolicy{AllowPrivateNetworkJWKS: s.cfg.Applications.AllowPrivateNetworkJWKS}
}

func NormalizeRemoteAppTrustSource(jwksURI string, mode string, keys []RemoteAppKey, policy TrustSourcePolicy) (string, error) {
	allowInsecureJWKS := policy.AllowPrivateNetworkJWKS
	mode = strings.ToLower(strings.TrimSpace(mode))
	jwksURI = strings.TrimSpace(jwksURI)
	if mode == "" {
		if len(keys) > 0 {
			mode = RemoteAppModeStatic
		} else {
			mode = RemoteAppModeJWKS
		}
	}
	switch mode {
	case RemoteAppModeJWKS:
		if jwksURI == "" {
			return "", fmt.Errorf("%w: jwks mode requires jwks_uri", ErrInvalidRemoteApplication)
		}
		if len(keys) > 0 {
			return "", fmt.Errorf("%w: jwks_uri and public_keys are mutually exclusive — register one trust source, never both", ErrInvalidRemoteApplication)
		}
		if err := validateJWKSURI(jwksURI, allowInsecureJWKS); err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidRemoteApplication, err)
		}
	case RemoteAppModeStatic:
		if len(keys) == 0 {
			return "", fmt.Errorf("%w: static mode requires a non-empty public_keys list", ErrInvalidRemoteApplication)
		}
		if jwksURI != "" {
			return "", fmt.Errorf("%w: jwks_uri and public_keys are mutually exclusive — register one trust source, never both", ErrInvalidRemoteApplication)
		}
		for i, k := range keys {
			if err := validatePublicKeyPEM(k.PublicKeyPEM); err != nil {
				return "", fmt.Errorf("%w: public_keys[%d]: %v", ErrInvalidRemoteApplication, i, err)
			}
		}
	default:
		return "", fmt.Errorf("%w: unknown mode %q (want jwks|static)", ErrInvalidRemoteApplication, mode)
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
// allowInsecure (Applications.AllowPrivateNetworkJWKS) permits http and
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

// validatePublicKeyPEM accepts PKIX ("PUBLIC KEY") and PKCS1 ("RSA PUBLIC
// KEY") blocks — same shapes the verifier's static-key path parses.
func validatePublicKeyPEM(raw string) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return errors.New("not a PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return fmt.Errorf("invalid PKIX public key: %v", err)
		}
	case "RSA PUBLIC KEY":
		if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return fmt.Errorf("invalid PKCS1 public key: %v", err)
		}
	default:
		return fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	return nil
}

func decodeRemoteAppKeys(raw []byte) []RemoteAppKey {
	if len(raw) == 0 {
		return nil
	}
	var keys []RemoteAppKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil
	}
	return keys
}

// RemoteApplication is a federation principal: an external system that
// authenticates by signing JWTs verified against its JWKS/public keys. Defined
// in authkit (core-free) and re-exported here.
type RemoteApplication = authkit.RemoteApplication

// remoteAppRow is the canonical remote_application projection every sqlc query
// returns; the per-query row structs are field-identical and convert directly.
type remoteAppRow = db.RemoteApplicationBySlugRow

func remoteAppFromRow(row remoteAppRow) *RemoteApplication {
	ra := &RemoteApplication{
		ID: row.ID, Slug: row.Slug, PermissionGroupID: row.PermissionGroupID,
		Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode,
		PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Enabled: row.Enabled,
		DisplayName: row.DisplayName, Tier: row.Tier, TrustRoot: row.TrustRoot,
		Domain:           row.Domain,
		DocumentEndpoint: row.DocumentEndpoint,
		CreatedAt:        row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	if row.RootVerifiedAt != nil {
		ra.RootVerifiedAt = *row.RootVerifiedAt
	}
	return ra
}

// UpsertRemoteApplication registers or updates a remote_application keyed by its
// issuer. An existing issuer can only be updated by its controlling group.
func (s *Service) UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug := strings.ToLower(strings.TrimSpace(in.Slug))
	issuer := strings.TrimSpace(in.Issuer)
	jwksURI := strings.TrimSpace(in.JWKSURI)
	if slug == "" || issuer == "" {
		return nil, ErrInvalidRemoteApplication
	}
	if !authkit.ValidRemoteApplicationIssuer(issuer) {
		return nil, fmt.Errorf("%w: issuer must be an absolute http(s) URL of at most %d bytes", ErrInvalidRemoteApplication, authkit.MaxRemoteApplicationIssuerLen)
	}
	// AK-AUTH-01: a remote_application must never claim the platform's own
	// issuer. The verifier keys issuers by string and upserts by issuer, so a
	// federated registration under the platform issuer would overwrite the
	// trusted local entry, swapping the platform's signing keys and breaking
	// verification of all first-party tokens. Reject case-insensitively to deny
	// trivial host-case bypasses. This guards every caller, including bootstrap.
	if platformIssuer := strings.TrimSpace(s.cfg.Token.Issuer); platformIssuer != "" && strings.EqualFold(issuer, platformIssuer) {
		return nil, ErrReservedIssuer
	}
	if err := validateRemoteAppSlug(slug); err != nil {
		return nil, ErrInvalidRemoteApplication
	}
	mode, err := NormalizeRemoteAppTrustSource(jwksURI, in.Mode, in.PublicKeys, s.trustSourcePolicy())
	if err != nil {
		return nil, err
	}
	var keysJSON []byte
	if mode == RemoteAppModeStatic {
		keysJSON, err = json.Marshal(in.PublicKeys)
		if err != nil {
			return nil, ErrInvalidRemoteApplication
		}
	}
	// Remote applications are group-nested: every issuer maps to one controlling
	// permission group.
	t := strings.TrimSpace(in.PermissionGroupID)
	if t == "" {
		return nil, fmt.Errorf("%w: permission_group_id is required (remote-applications are group-nested)", ErrInvalidRemoteApplication)
	}
	groupID := &t
	existing, err := s.q.RemoteApplicationByIssuer(ctx, issuer)
	if err == nil && existing.PermissionGroupID != t {
		return nil, ErrRemoteApplicationIssuerConflict
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("look up remote application issuer: %w", err)
	}

	row, err := s.q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{
		Slug:              slug,
		PermissionGroupID: groupID,
		Issuer:            issuer,
		JwksUri:           jwksURI,
		Mode:              mode,
		PublicKeys:        keysJSON,
		Enabled:           in.Enabled,
	})
	// The atomic upsert guard also covers an issuer claimed after our lookup.
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRemoteApplicationIssuerConflict
	}
	if err != nil {
		return nil, err
	}
	return remoteAppFromRow(remoteAppRow(row)), nil
}

// GetRemoteApplication returns a remote_application by OIDC issuer URL.
func (s *Service) GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, ErrInvalidRemoteApplication
	}
	row, err := s.q.RemoteApplicationByIssuer(ctx, issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRemoteApplicationNotFound
	}
	if err != nil {
		return nil, err
	}
	// Issuer lookups are verification-facing: a disabled application must fail
	// closed on the next request, not at the next reconcile (#323). Admin reads
	// use GetRemoteApplicationBySlug / ListRemoteApplications.
	if !row.Enabled {
		return nil, ErrRemoteApplicationNotFound
	}
	return remoteAppFromRow(remoteAppRow(row)), nil
}

// GetRemoteApplicationBySlug returns a remote_application by slug.
func (s *Service) GetRemoteApplicationBySlug(ctx context.Context, slug string) (*RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return nil, ErrInvalidRemoteApplication
	}
	row, err := s.q.RemoteApplicationBySlug(ctx, slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRemoteApplicationNotFound
	}
	if err != nil {
		return nil, err
	}
	return remoteAppFromRow(row), nil
}

// ListRemoteApplications returns every registered remote_application,
// enabled or not (the admin read).
func (s *Service) ListRemoteApplications(ctx context.Context) ([]RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	rows, err := s.q.RemoteApplicationsAll(ctx)
	if err != nil {
		return nil, err
	}
	var out []RemoteApplication
	for _, r := range rows {
		out = append(out, *remoteAppFromRow(remoteAppRow(r)))
	}
	return out, nil
}

// ListEnabledRemoteApplications returns only the enabled remote_applications:
// the verification-facing snapshot a Verifier trusts issuers from.
func (s *Service) ListEnabledRemoteApplications(ctx context.Context) ([]RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	rows, err := s.q.RemoteApplicationsEnabled(ctx)
	if err != nil {
		return nil, err
	}
	var out []RemoteApplication
	for _, r := range rows {
		out = append(out, *remoteAppFromRow(remoteAppRow(r)))
	}
	return out, nil
}

// ListRemoteApplicationsForGroup returns the remote_applications whose
// controlling permission_group_id is the group addressed by (persona,
// instanceSlug) (#111). It resolves the group via the store, then filters
// remote_applications by permission_group_id so a per-persona management caller
// sees only the issuers it controls (ListRemoteApplications lists ALL groups').
func (s *Service) ListRemoteApplicationsForGroup(ctx context.Context, group authkit.GroupRef) ([]RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return nil, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT id::text, slug, COALESCE(permission_group_id::text, ''), issuer, COALESCE(jwks_uri,''),
		        mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint,
		        root_verified_at, created_at, updated_at
		 FROM profiles.remote_applications
		 WHERE permission_group_id = $1::uuid
		 ORDER BY created_at DESC`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RemoteApplication, 0)
	for rows.Next() {
		var (
			ra         RemoteApplication
			rawKeys    []byte
			verifiedAt *time.Time
		)
		if err := rows.Scan(&ra.ID, &ra.Slug, &ra.PermissionGroupID, &ra.Issuer, &ra.JWKSURI,
			&ra.Mode, &rawKeys, &ra.Enabled, &ra.DisplayName, &ra.Tier, &ra.TrustRoot,
			&ra.Domain, &ra.DocumentEndpoint, &verifiedAt,
			&ra.CreatedAt, &ra.UpdatedAt); err != nil {
			return nil, err
		}
		ra.PublicKeys = decodeRemoteAppKeys(rawKeys)
		if verifiedAt != nil {
			ra.RootVerifiedAt = *verifiedAt
		}
		out = append(out, ra)
	}
	return out, rows.Err()
}

// DeleteRemoteApplication removes a remote_application by OIDC issuer URL.
func (s *Service) DeleteRemoteApplication(ctx context.Context, issuer string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ErrInvalidRemoteApplication
	}
	n, err := s.q.RemoteApplicationDelete(ctx, issuer)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrRemoteApplicationNotFound
	}
	return nil
}
