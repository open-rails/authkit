package embedded

// Application self-registration (#264): domain-proven remote applications.
//
// TRUST-ROOT DOCTRINE: the trust root is domain control (or an owning user
// account) — NEVER the keypair alone. The server-side fetch of
// https://<domain>/.well-known/authkit/application.json IS the domain-control
// proof; re-fetching it re-proves the root and adopts the document's CURRENT
// keys, so a keypair that is rotated, lost, or destroyed never strands the
// application.
//
// Registration buys EXISTENCE only (tier `registered`: authenticate + serve/
// fetch documents); `approved` is an admin act on the host. Identity is the
// uuidv7 row id. SLUGS AND DOMAINS ARE SEPARATE: the domain is the trust root
// and the re-registration key; the slug is a freely CLAIMED handle (requested
// in application.json, defaulting to the domain's hostname) that passes the
// same availability + anti-squat gates as any org slug.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/netguard"
)

// Re-exported sentinels (defined in authkit, core-free).
var (
	ErrApplicationRegistrationDisabled = authkit.ErrApplicationRegistrationDisabled
	ErrApplicationDomainInvalid        = authkit.ErrApplicationDomainInvalid
	ErrApplicationDomainConflict       = authkit.ErrApplicationDomainConflict
	ErrApplicationDocumentFetchFailed  = authkit.ErrApplicationDocumentFetchFailed
	ErrApplicationDocumentInvalid      = authkit.ErrApplicationDocumentInvalid
	ErrApplicationSlugConflict         = authkit.ErrApplicationSlugConflict
	ErrApplicationIssuerConflict       = authkit.ErrApplicationIssuerConflict
)

// Re-exported tier/trust-root constants and document types.
const (
	ApplicationTierRegistered = authkit.ApplicationTierRegistered
	ApplicationTierApproved   = authkit.ApplicationTierApproved

	ApplicationTrustRootManual = authkit.ApplicationTrustRootManual
	ApplicationTrustRootDomain = authkit.ApplicationTrustRootDomain
	ApplicationTrustRootUser   = authkit.ApplicationTrustRootUser

	ApplicationWellKnownPath = authkit.ApplicationWellKnownPath
)

type ApplicationDocument = authkit.ApplicationDocument
type RegisteredApplication = authkit.RegisteredApplication

const (
	// maxApplicationDocumentBytes caps the application.json (and JWKS) fetch.
	maxApplicationDocumentBytes = 64 << 10
	// maxDisplayNameBytes caps free-form display names.
	maxDisplayNameBytes = 256
)

func truncateDisplayName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > maxDisplayNameBytes {
		name = name[:maxDisplayNameBytes]
	}
	return name
}

// newApplicationsHTTPClient builds the outbound client for application.json
// and JWKS fetches: timeout-bounded, redirect-refusing, and (outside dev)
// dialing only public addresses after resolving the host itself. r overrides
// the resolver (tests); nil uses the system resolver.
func newApplicationsHTTPClient(allowPrivate bool, r netguard.Resolver) *http.Client {
	if r == nil {
		r = net.DefaultResolver
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: netguard.TransportWith(r, allowPrivate),
		// A redirect out of the proven domain would decouple the fetch from the
		// domain-control proof (and is a classic SSRF pivot).
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: redirects are not followed", ErrApplicationDocumentFetchFailed)
		},
	}
}

// resolveApplicationDomain normalizes the registration `domain` input into
// the CANONICAL domain (the stored trust-root key), the hostname, and the
// document fetch URL.
//
// Outside dev-like environments the input must be a bare lowercase DNS name —
// no scheme, port, path, userinfo, or IP literal — and the fetch is always
// https (canonical == host). Dev-like environments additionally accept a full
// http(s) base URL (e.g. http://127.0.0.1:8080) for loopback rigs — the
// canonical form keeps scheme+port so distinct rigs stay distinct roots; that
// is the #257-style dev carve-out, and 127.0.0.1 obviously cannot
// domain-prove anything in prod.
func (s *Client) resolveApplicationDomain(domain string) (canonical, host, fetchURL string, err error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", "", "", fmt.Errorf("%w: domain is required", ErrApplicationDomainInvalid)
	}
	isDev := s.cfg.Applications.AllowPrivateNetworkJWKS
	if strings.Contains(domain, "://") {
		if !isDev {
			return "", "", "", fmt.Errorf("%w: domain must be a bare DNS name (no scheme)", ErrApplicationDomainInvalid)
		}
		u, err := url.Parse(domain)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return "", "", "", fmt.Errorf("%w: dev domain must be a plain http(s) base URL", ErrApplicationDomainInvalid)
		}
		canonical = u.Scheme + "://" + strings.ToLower(u.Host)
		return canonical, strings.ToLower(u.Hostname()), canonical + ApplicationWellKnownPath, nil
	}
	host = strings.ToLower(domain)
	if strings.ContainsAny(host, "/@:? #") {
		return "", "", "", fmt.Errorf("%w: domain must be a bare DNS name", ErrApplicationDomainInvalid)
	}
	if err := validateRemoteAppSlug(host); err != nil {
		return "", "", "", fmt.Errorf("%w: %q is not a valid DNS name", ErrApplicationDomainInvalid, domain)
	}
	if !isDev {
		if net.ParseIP(host) != nil {
			return "", "", "", fmt.Errorf("%w: IP literals cannot domain-prove", ErrApplicationDomainInvalid)
		}
		if netguard.IsInternalHostname(host) || !strings.Contains(host, ".") {
			return "", "", "", fmt.Errorf("%w: %q is not a public DNS name", ErrApplicationDomainInvalid, host)
		}
	}
	return host, host, "https://" + host + ApplicationWellKnownPath, nil
}

// fetchApplicationDocument GETs the well-known application.json. The fetch is
// the domain-control proof, so its transport is deliberately strict: bounded
// body, no redirects, SSRF-guarded dials outside dev.
func (s *Client) fetchApplicationDocument(ctx context.Context, fetchURL string) (*ApplicationDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApplicationDocumentFetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.appHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApplicationDocumentFetchFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s returned %d", ErrApplicationDocumentFetchFailed, fetchURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxApplicationDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApplicationDocumentFetchFailed, err)
	}
	if len(body) > maxApplicationDocumentBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrApplicationDocumentInvalid, maxApplicationDocumentBytes)
	}
	var doc ApplicationDocument
	// Unknown fields are tolerated (forward-compatible document schema).
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrApplicationDocumentInvalid, err)
	}
	return &doc, nil
}

// normalizedApplication is a validated application.json ready to persist.
type normalizedApplication struct {
	Slug             string
	DisplayName      string
	Issuer           string
	JWKSURI          string
	Mode             string
	KeysJSON         []byte
	DocumentEndpoint string
}

// validateApplicationDocument enforces the document contract against the
// PROVEN host: issuer host == domain outside dev-like environments (a domain
// proof must never mint authority over someone else's issuer namespace),
// exactly one trust source, and public https URLs. The slug is a FREE CLAIM
// (defaulting to the hostname) — availability is checked at claim time, not
// here.
func (s *Client) validateApplicationDocument(doc *ApplicationDocument, host string) (*normalizedApplication, error) {
	isDev := s.cfg.Applications.AllowPrivateNetworkJWKS
	slug := strings.ToLower(strings.TrimSpace(doc.Slug))
	if slug == "" {
		slug = host
	}
	if err := validateRemoteAppSlug(slug); err != nil {
		return nil, fmt.Errorf("%w: invalid slug %q", ErrApplicationDocumentInvalid, slug)
	}

	issuer := strings.TrimSpace(doc.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrApplicationDocumentInvalid)
	}
	iu, err := url.Parse(issuer)
	if err != nil || (iu.Scheme != "http" && iu.Scheme != "https") || iu.Hostname() == "" {
		return nil, fmt.Errorf("%w: issuer must be an http(s) URL", ErrApplicationDocumentInvalid)
	}
	if !isDev {
		if iu.Scheme != "https" {
			return nil, fmt.Errorf("%w: issuer must use https", ErrApplicationDocumentInvalid)
		}
		if !strings.EqualFold(iu.Hostname(), host) {
			return nil, fmt.Errorf("%w: issuer host %q must equal the serving domain %q", ErrApplicationDocumentInvalid, iu.Hostname(), host)
		}
	}
	if platformIssuer := strings.TrimSpace(s.cfg.Token.Issuer); platformIssuer != "" && strings.EqualFold(issuer, platformIssuer) {
		return nil, ErrReservedIssuer
	}

	mode, err := NormalizeRemoteAppTrustSource(strings.TrimSpace(doc.JWKSURI), "", doc.PublicKeys, TrustSourcePolicy{AllowPrivateNetworkJWKS: isDev})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApplicationDocumentInvalid, err)
	}
	var keysJSON []byte
	if mode == RemoteAppModeStatic {
		keysJSON, err = json.Marshal(doc.PublicKeys)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrApplicationDocumentInvalid, err)
		}
	}

	endpoint := strings.TrimSpace(doc.DocumentEndpoint)
	if endpoint != "" {
		if err := validateJWKSURI(endpoint, isDev); err != nil {
			return nil, fmt.Errorf("%w: document_endpoint: %v", ErrApplicationDocumentInvalid, err)
		}
	}

	return &normalizedApplication{
		Slug:             slug,
		DisplayName:      truncateDisplayName(doc.DisplayName),
		Issuer:           issuer,
		JWKSURI:          strings.TrimSpace(doc.JWKSURI),
		Mode:             mode,
		KeysJSON:         keysJSON,
		DocumentEndpoint: endpoint,
	}, nil
}

func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, constraint)
}

// applicationsEnabled validates the self-registration configuration and
// returns the org persona definition.
func (s *Client) applicationsEnabled() (PersonaDef, error) {
	if !s.cfg.Applications.SelfRegistration {
		return PersonaDef{}, ErrApplicationRegistrationDisabled
	}
	persona := authkit.Persona(strings.TrimSpace(string(s.cfg.Applications.OrgPersona)))
	td, ok := s.groupSchemaOrDefault().Persona(persona)
	if !ok || persona == RootPersona || td.Parent != RootPersona {
		return PersonaDef{}, fmt.Errorf("%w: Applications.OrgPersona %q must be a declared persona parented by root", ErrApplicationRegistrationDisabled, persona)
	}
	return td, nil
}

// RegisterApplicationFromDomain is the create-or-reprove registration flow
// (#264): fetch + validate the domain's application.json (the domain-control
// proof), then atomically create the remote_application row + its
// SERVICE-OWNED org (the application principal is the org's owner) — or, when
// the slug already exists as a domain-rooted application, refresh its
// issuer/keys/config from the re-fetched document. Re-registration is the
// boot-time self-heal AND the rotation-from-root path: the old keypair may be
// gone entirely, the fresh domain proof adopts whatever the document declares
// now.
func (s *Client) RegisterApplicationFromDomain(ctx context.Context, domain string) (*RegisteredApplication, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	td, err := s.applicationsEnabled()
	if err != nil {
		return nil, err
	}
	canonical, host, fetchURL, err := s.resolveApplicationDomain(domain)
	if err != nil {
		return nil, err
	}
	if s.appAdmission != nil {
		if err := s.appAdmission(ctx, canonical); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrApplicationRegistrationDisabled, err)
		}
	}
	doc, err := s.fetchApplicationDocument(ctx, fetchURL)
	if err != nil {
		return nil, err
	}
	app, err := s.validateApplicationDocument(doc, host)
	if err != nil {
		return nil, err
	}
	// Outside the tx: a singleton-index race inside it would abort the whole
	// registration (#258); EnsureRootGroup self-heals on the pool.
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return nil, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	dbtx := db.ForSchema(tx, s.dbSchema())
	q := db.New(dbtx)
	st := s.groupStoreFor(dbtx)

	// Idempotent re-registration is keyed by the DOMAIN (the trust root). The
	// slug was claimed at first registration and is NOT changed by a refresh —
	// the document's slug field only matters for the initial claim.
	existing, err := q.RemoteApplicationByDomainForUpdate(ctx, canonical)
	switch {
	case err == nil:
		if existing.TrustRoot != ApplicationTrustRootDomain {
			return nil, ErrApplicationDomainConflict
		}
		row, err := q.RemoteApplicationDomainRefresh(ctx, db.RemoteApplicationDomainRefreshParams{
			Issuer:           app.Issuer,
			JwksUri:          app.JWKSURI,
			Mode:             app.Mode,
			PublicKeys:       app.KeysJSON,
			DisplayName:      app.DisplayName,
			DocumentEndpoint: app.DocumentEndpoint,
			Domain:           canonical,
		})
		if isUniqueViolation(err, "issuer") {
			return nil, ErrApplicationIssuerConflict
		}
		if err != nil {
			return nil, err
		}
		// Keep the service-owned org's vanity name in sync and make sure the
		// owner assignment exists (self-heal).
		if row.PermissionGroupID != "" {
			if err := st.SetGroupDisplayName(ctx, row.PermissionGroupID, app.DisplayName); err != nil {
				return nil, err
			}
			if err := st.AssignRole(ctx, row.PermissionGroupID, authkit.RemoteAppSubject(row.ID), OwnerRoleName); err != nil {
				return nil, err
			}
		}
		orgPersona, orgSlug, err := groupAddressByID(ctx, dbtx, row.PermissionGroupID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &RegisteredApplication{
			Application:     *remoteAppFromRow(remoteAppRow(row)),
			OrgPersona:      orgPersona,
			OrgInstanceSlug: orgSlug,
			Created:         false,
		}, nil
	case errors.Is(err, pgx.ErrNoRows):
		// fresh registration below
	default:
		return nil, err
	}

	// First registration CLAIMS the requested slug — the same availability +
	// anti-squat gates as any org: not reserved by the persona (#296), free in
	// the application namespace AND in the org persona namespace (live groups
	// + tombstones).
	if slugReserved(td.Creation.ReservedSlugs, app.Slug) {
		return nil, fmt.Errorf("%w: slug %q is reserved", ErrApplicationSlugConflict, app.Slug)
	}
	if _, err := q.RemoteApplicationBySlugForUpdate(ctx, app.Slug); err == nil {
		return nil, ErrApplicationSlugConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if available, err := st.InstanceSlugAvailable(ctx, authkit.GroupRef{Persona: td.Name, Instance: app.Slug}); err != nil {
		return nil, err
	} else if !available {
		return nil, ErrApplicationSlugConflict
	}
	rootGID, err := st.RootGroupID(ctx)
	if err != nil {
		return nil, err
	}
	gid, err := st.CreateGroupNamed(ctx, authkit.GroupRef{Persona: td.Name, Instance: app.Slug}, rootGID, app.DisplayName)
	if err != nil {
		return nil, err
	}
	row, err := q.RemoteApplicationDomainInsert(ctx, db.RemoteApplicationDomainInsertParams{
		Slug:              app.Slug,
		PermissionGroupID: &gid,
		Issuer:            app.Issuer,
		JwksUri:           app.JWKSURI,
		Mode:              app.Mode,
		PublicKeys:        app.KeysJSON,
		DisplayName:       app.DisplayName,
		Domain:            canonical,
		DocumentEndpoint:  app.DocumentEndpoint,
	})
	switch {
	case isUniqueViolation(err, "issuer"):
		return nil, ErrApplicationIssuerConflict
	case isUniqueViolation(err, "domain"):
		return nil, ErrApplicationDomainConflict
	case isUniqueViolation(err, "slug"):
		return nil, ErrApplicationSlugConflict
	case err != nil:
		return nil, err
	}
	// Client-owned org: the application principal owns its own group. Zero
	// authority outside its persona namespace by construction.
	if err := st.AssignRole(ctx, gid, authkit.RemoteAppSubject(row.ID), OwnerRoleName); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &RegisteredApplication{
		Application:     *remoteAppFromRow(remoteAppRow(row)),
		OrgPersona:      td.Name,
		OrgInstanceSlug: app.Slug,
		Created:         true,
	}, nil
}

func groupAddressByID(ctx context.Context, dbtx db.DBTX, groupID string) (persona authkit.Persona, instanceSlug string, err error) {
	if groupID == "" {
		return "", "", nil
	}
	err = dbtx.QueryRow(ctx,
		`SELECT persona, COALESCE(instance_slug, '') FROM profiles.permission_groups WHERE id = $1::uuid`,
		groupID).Scan(&persona, &instanceSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	return persona, instanceSlug, err
}
