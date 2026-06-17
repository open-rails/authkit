package core

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

var (
	// ErrRemoteApplicationNotFound indicates no remote_application matched.
	ErrRemoteApplicationNotFound = errors.New("remote_application_not_found")
	// ErrInvalidRemoteApplication indicates a malformed registration payload.
	ErrInvalidRemoteApplication = errors.New("invalid_remote_application")
)

// Remote-application trust modes (#74). A remote_application is a federation
// PRINCIPAL whose credential is a key, with exactly one trust source:
//
//	jwks   — keys fetched + refreshed from JWKSURI; rotation is publishing a new
//	         kid at the same URL.
//	static — authorized_keys-style human-managed PEM list for principals without
//	         a JWKS endpoint; manual rotation by design.
const (
	RemoteAppModeJWKS   = "jwks"
	RemoteAppModeStatic = "static"
)

// RemoteAppKey is one entry of a static-mode principal's human-managed key list
// (stored as jsonb; edited like an authorized_keys file).
type RemoteAppKey struct {
	KID          string `json:"kid,omitempty" yaml:"kid,omitempty"`
	PublicKeyPEM string `json:"public_key_pem" yaml:"public_key_pem"`
}

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
// authenticates by signing JWTs verified against its JWKS/public keys. It is
// optionally owned by an org and may hold org memberships with roles via the
// same polymorphic membership machinery as users (#74).
type RemoteApplication struct {
	ID      string
	Slug    string
	OrgID   string // optional controlling org; empty means bootstrap/operator-managed
	Issuer  string // OIDC iss
	JWKSURI string // OIDC jwks_uri (jwks mode only)
	// Mode is the trust source: RemoteAppModeJWKS (fetch from JWKSURI) XOR
	// RemoteAppModeStatic (human-managed PublicKeys list). Never both.
	Mode string
	// PublicKeys is the static-mode key list (empty in jwks mode).
	PublicKeys []RemoteAppKey
	Audiences  []string
	Enabled    bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func remoteAppFromUpsert(row db.RemoteApplicationUpsertRow) *RemoteApplication {
	return &RemoteApplication{ID: row.ID, Slug: row.Slug, OrgID: row.OrgID, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Audiences: row.Audiences, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

// UpsertRemoteApplication registers or updates a remote_application keyed by its
// issuer. OrgID is optional: empty rows are bootstrap/operator-managed.
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
	if err := validateOrgSlug(slug); err != nil {
		return nil, ErrInvalidRemoteApplication
	}
	mode, err := NormalizeRemoteAppTrustSource(jwksURI, in.Mode, in.PublicKeys)
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
	var org *string
	if t := strings.TrimSpace(in.OrgID); t != "" {
		org = &t
	}

	row, err := s.q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{
		Slug:       slug,
		OrgID:      org,
		Issuer:     issuer,
		JwksUri:    jwksURI,
		Mode:       mode,
		PublicKeys: keysJSON,
		Audiences:  dedupeStrings(in.Audiences),
		Enabled:    in.Enabled,
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
	return &RemoteApplication{ID: row.ID, Slug: row.Slug, OrgID: row.OrgID, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Audiences: row.Audiences, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

// ResolveRemoteApplicationOrg returns the owning org_id of the
// remote_application registered for issuer (#77). Empty string means
// unowned/bootstrap-managed; ErrRemoteApplicationNotFound if unknown.
func (s *Service) ResolveRemoteApplicationOrg(ctx context.Context, issuer string) (string, error) {
	ra, err := s.GetRemoteApplication(ctx, issuer)
	if err != nil {
		return "", err
	}
	return ra.OrgID, nil
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
	return &RemoteApplication{ID: row.ID, Slug: row.Slug, OrgID: row.OrgID, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeRemoteAppKeys(row.PublicKeys), Audiences: row.Audiences, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
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
			out = append(out, RemoteApplication{ID: r.ID, Slug: r.Slug, OrgID: r.OrgID, Issuer: r.Issuer, JWKSURI: r.JwksUri, Mode: r.Mode, PublicKeys: decodeRemoteAppKeys(r.PublicKeys), Audiences: r.Audiences, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
		}
		return out, nil
	}
	rows, err := s.q.RemoteApplicationsAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, RemoteApplication{ID: r.ID, Slug: r.Slug, OrgID: r.OrgID, Issuer: r.Issuer, JWKSURI: r.JwksUri, Mode: r.Mode, PublicKeys: decodeRemoteAppKeys(r.PublicKeys), Audiences: r.Audiences, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
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
