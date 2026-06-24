package authcore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/authbase"
	"github.com/open-rails/authkit/internal/db"
)

// remoteAppSlugRe validates a remote_application slug: lowercase alnum with
// internal hyphens.
var remoteAppSlugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func validateRemoteAppSlug(slug string) error {
	if slug == "" || len(slug) > 63 || !remoteAppSlugRe.MatchString(slug) {
		return ErrInvalidRemoteApplication
	}
	return nil
}

var (
	// ErrRemoteApplicationNotFound indicates no remote_application matched.
	ErrRemoteApplicationNotFound = errors.New("remote_application_not_found")
	// ErrInvalidRemoteApplication is defined in authbase and re-exported here.
	ErrInvalidRemoteApplication = authbase.ErrInvalidRemoteApplication
	// ErrReservedIssuer indicates an attempt to register a remote_application
	// under the platform's own issuer string. The platform issuer is the local,
	// first-party signing identity; allowing a federated remote_application to
	// claim it would overwrite the trusted local issuer entry (key-swap / auth
	// DoS — see AK-AUTH-01).
	ErrReservedIssuer = errors.New("reserved_issuer")
)

// Remote-application trust modes (#74). A remote_application is a federation
// PRINCIPAL whose credential is a key, with exactly one trust source:
//
//	jwks   — keys fetched + refreshed from JWKSURI; rotation is publishing a new
//	         kid at the same URL.
//	static — authorized_keys-style human-managed PEM list for principals without
//	         a JWKS endpoint; manual rotation by design.
//
// Remote-application trust modes are defined in authbase (core-free) and
// re-exported here.
const (
	RemoteAppModeJWKS   = authbase.RemoteAppModeJWKS
	RemoteAppModeStatic = authbase.RemoteAppModeStatic
)

// RemoteAppKey is defined in authbase (core-free) and re-exported here.
type RemoteAppKey = authbase.RemoteAppKey

// NormalizeRemoteAppTrustSource validates the mutually-exclusive trust source of
// a registration and returns the normalized mode. Empty mode is inferred: a key
// list means static, otherwise jwks. It is the single validation gate so the XOR
// rule cannot be bypassed.
func NormalizeRemoteAppTrustSource(jwksURI string, mode string, keys []RemoteAppKey) (string, error) {
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
		if err := validateJWKSURI(jwksURI); err != nil {
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

// privateCoreCIDRs are address ranges that must never be the target of a
// jwks_uri fetch — cloud metadata, RFC-1918 private, loopback, link-local.
// Populated once at init; net.ParseCIDR never fails on these literals.
var privateCoreCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",          // unspecified / "this" network
		"10.0.0.0/8",         // RFC-1918 private
		"100.64.0.0/10",      // RFC-6598 carrier-grade NAT
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local — AWS/GCP instance metadata
		"172.16.0.0/12",      // RFC-1918 private
		"192.168.0.0/16",     // RFC-1918 private
		"198.18.0.0/15",      // RFC-2544 benchmarking
		"198.51.100.0/24",    // RFC-5737 documentation
		"203.0.113.0/24",     // RFC-5737 documentation
		"240.0.0.0/4",        // reserved (class E)
		"255.255.255.255/32", // broadcast
		"::1/128",            // IPv6 loopback
		"fc00::/7",           // IPv6 unique local
		"fe80::/10",          // IPv6 link-local
		"::/128",             // IPv6 unspecified
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateCoreCIDRs = append(privateCoreCIDRs, block)
	}
}

func isCorePrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, block := range privateCoreCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// validateJWKSURI rejects jwks_uri values that are:
//   - not HTTPS
//   - pointing at localhost or well-known internal hostnames
//   - using a literal private/reserved IP address
//
// This is a syntactic check (no DNS resolution). The verifier's SSRF-guarding
// dialer provides a second layer against DNS rebinding at fetch time.
func validateJWKSURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("jwks_uri is not a valid URL: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("jwks_uri must use https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("jwks_uri must have a non-empty host")
	}
	// Block well-known internal hostnames by name (case-insensitive).
	// Covers localhost, cloud-metadata aliases, Docker/Podman host-access
	// magic names, and any *.docker.internal / *.containers.internal suffix.
	lower := strings.ToLower(host)
	switch {
	case lower == "localhost",
		strings.HasSuffix(lower, ".localhost"),
		// Cloud instance metadata
		lower == "metadata",
		lower == "metadata.google.internal",
		lower == "169.254.169.254", // belt-and-suspenders for non-IP literal path
		// Docker Desktop / Docker Engine host-gateway names
		lower == "host.docker.internal",
		lower == "gateway.docker.internal",
		lower == "kubernetes.docker.internal",
		lower == "host-gateway",
		strings.HasSuffix(lower, ".docker.internal"),
		// Podman / newer OCI runtimes
		lower == "host.containers.internal",
		strings.HasSuffix(lower, ".containers.internal"):
		return fmt.Errorf("jwks_uri host %q is not a public address", host)
	}
	// If the host is a literal IP, reject private/reserved ranges immediately.
	if ip := net.ParseIP(host); ip != nil {
		if isCorePrivateIP(ip) {
			return fmt.Errorf("jwks_uri %q resolves to a private/reserved IP — not allowed", host)
		}
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

// Origin helpers are defined in authbase (core-free) and re-exported here.
var (
	NormalizeAllowedOrigin  = authbase.NormalizeAllowedOrigin
	NormalizeAllowedOrigins = authbase.NormalizeAllowedOrigins
	OriginAllowed           = authbase.OriginAllowed
)

// RemoteApplication is a federation principal: an external system that
// authenticates by signing JWTs verified against its JWKS/public keys. Defined
// in authbase (core-free) and re-exported here.
type RemoteApplication = authbase.RemoteApplication

func remoteAppFromUpsert(row db.RemoteApplicationUpsertRow) *RemoteApplication {
	return &RemoteApplication{ID: row.ID, Slug: row.Slug, PermissionGroupID: row.PermissionGroupID, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Audiences: row.Audiences, AllowedOrigins: row.AllowedOrigins, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

// UpsertRemoteApplication registers or updates a remote_application keyed by its
// issuer.
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
	// AK-AUTH-01: a remote_application must never claim the platform's own
	// issuer. The verifier keys issuers by string and upserts by issuer, so a
	// federated registration under the platform issuer would overwrite the
	// trusted local entry, swapping the platform's signing keys and breaking
	// verification of all first-party tokens. Reject case-insensitively to deny
	// trivial host-case bypasses. This guards every caller, including bootstrap.
	if platformIssuer := strings.TrimSpace(s.opts.Issuer); platformIssuer != "" && strings.EqualFold(issuer, platformIssuer) {
		return nil, ErrReservedIssuer
	}
	if err := validateRemoteAppSlug(slug); err != nil {
		return nil, ErrInvalidRemoteApplication
	}
	mode, err := NormalizeRemoteAppTrustSource(jwksURI, in.Mode, in.PublicKeys)
	if err != nil {
		return nil, err
	}
	allowedOrigins, err := NormalizeAllowedOrigins(in.AllowedOrigins)
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

	row, err := s.q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{
		Slug:              slug,
		PermissionGroupID: groupID,
		Issuer:            issuer,
		JwksUri:           jwksURI,
		Mode:              mode,
		PublicKeys:        keysJSON,
		Audiences:         dedupeStrings(in.Audiences),
		AllowedOrigins:    allowedOrigins,
		Enabled:           in.Enabled,
	})
	if err != nil {
		return nil, err
	}
	return remoteAppFromUpsert(row), nil
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
	return &RemoteApplication{ID: row.ID, Slug: row.Slug, PermissionGroupID: row.PermissionGroupID, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Audiences: row.Audiences, AllowedOrigins: row.AllowedOrigins, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

// ResolveRemoteApplicationGroup returns the controlling permission_group_id of
// the remote_application registered for issuer (#111). ErrRemoteApplicationNotFound
// if unknown.
func (s *Service) ResolveRemoteApplicationGroup(ctx context.Context, issuer string) (string, error) {
	ra, err := s.GetRemoteApplication(ctx, issuer)
	if err != nil {
		return "", err
	}
	return ra.PermissionGroupID, nil
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
	return &RemoteApplication{ID: row.ID, Slug: row.Slug, PermissionGroupID: row.PermissionGroupID, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Audiences: row.Audiences, AllowedOrigins: row.AllowedOrigins, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

// ListRemoteApplications returns registered remote_applications. When activeOnly
// is true, only enabled rows are returned.
func (s *Service) ListRemoteApplications(ctx context.Context, activeOnly bool) ([]RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	var out []RemoteApplication
	if activeOnly {
		rows, err := s.q.RemoteApplicationsEnabled(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, RemoteApplication{ID: r.ID, Slug: r.Slug, PermissionGroupID: r.PermissionGroupID, Issuer: r.Issuer, JWKSURI: r.JwksUri, Mode: r.Mode, PublicKeys: decodeRemoteAppKeys(r.PublicKeys), Audiences: r.Audiences, AllowedOrigins: r.AllowedOrigins, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
		}
		return out, nil
	}
	rows, err := s.q.RemoteApplicationsAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, RemoteApplication{ID: r.ID, Slug: r.Slug, PermissionGroupID: r.PermissionGroupID, Issuer: r.Issuer, JWKSURI: r.JwksUri, Mode: r.Mode, PublicKeys: decodeRemoteAppKeys(r.PublicKeys), Audiences: r.Audiences, AllowedOrigins: r.AllowedOrigins, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}

// ListRemoteApplicationsForGroup returns the remote_applications whose
// controlling permission_group_id is the group addressed by (persona,
// instanceSlug) (#111). It resolves the group via the store, then filters
// remote_applications by permission_group_id so a per-persona management caller
// sees only the issuers it controls (ListRemoteApplications lists ALL groups').
func (s *Service) ListRemoteApplicationsForGroup(ctx context.Context, persona, instanceSlug string) ([]RemoteApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(persona), strings.TrimSpace(instanceSlug))
	if err != nil {
		return nil, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT id::text, slug, COALESCE(permission_group_id::text, ''), issuer, COALESCE(jwks_uri,''),
		        mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
		 FROM profiles.remote_applications
		 WHERE permission_group_id = $1::uuid AND deleted_at IS NULL
		 ORDER BY created_at DESC`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RemoteApplication, 0)
	for rows.Next() {
		var (
			ra      RemoteApplication
			rawKeys []byte
		)
		if err := rows.Scan(&ra.ID, &ra.Slug, &ra.PermissionGroupID, &ra.Issuer, &ra.JWKSURI,
			&ra.Mode, &rawKeys, &ra.Audiences, &ra.AllowedOrigins, &ra.Enabled,
			&ra.CreatedAt, &ra.UpdatedAt); err != nil {
			return nil, err
		}
		ra.PublicKeys = decodeRemoteAppKeys(rawKeys)
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
