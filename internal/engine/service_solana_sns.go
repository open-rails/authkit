package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/netguard"
)

const (
	defaultSolanaSNSLookupTimeout = 3 * time.Second
	defaultSolanaSNSCacheTTL      = 24 * time.Hour

	solanaSNSStatusPending  = "pending"
	solanaSNSStatusResolved = "resolved"
	solanaSNSStatusNotFound = "not_found"
	solanaSNSStatusError    = "error"
	solanaSNSStatusStale    = "stale"

	solanaSNSProviderError     = "resolver_error"
	solanaSNSInvalidNameError  = "invalid_sns_name"
	solanaSNSProfilePrimaryKey = "sns_primary_name"
)

var defaultSolanaSNSProxyURL = "https://sdk-proxy.sns.id"

// SolanaSNSResolver mirrors authkit.SolanaSNSResolver.
type SolanaSNSResolver interface {
	ResolvePrimaryName(ctx context.Context, address string) (string, error)
}

type defaultSolanaSNSResolver struct {
	client  *http.Client
	baseURL string
}

func newDefaultSolanaSNSResolver() defaultSolanaSNSResolver {
	return defaultSolanaSNSResolver{
		client:  netguard.Client(defaultSolanaSNSLookupTimeout, false),
		baseURL: defaultSolanaSNSProxyURL,
	}
}

func (r defaultSolanaSNSResolver) ResolvePrimaryName(ctx context.Context, address string) (string, error) {
	baseURL := strings.TrimRight(r.baseURL, "/")
	if baseURL == "" {
		baseURL = defaultSolanaSNSProxyURL
	}
	endpoint := baseURL + "/favorite-domain/" + url.PathEscape(strings.TrimSpace(address))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("sns proxy status %d", resp.StatusCode)
	}
	var body struct {
		Status string `json:"s"`
		Result struct {
			Reverse string `json:"reverse"`
			Domain  string `json:"domain"`
			Stale   bool   `json:"stale"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Status != "ok" {
		return "", fmt.Errorf("sns proxy status %q", body.Status)
	}
	// stale=true means the wallet set this as its favorite/primary domain but has
	// since transferred or sold it — it no longer owns the name. Treat as no
	// primary name so AuthKit never displays a .sol name the user gave up.
	if body.Result.Stale {
		return "", nil
	}
	name := strings.TrimSpace(body.Result.Reverse)
	if name == "" {
		return "", nil
	}
	if !strings.HasSuffix(strings.ToLower(name), ".sol") {
		name += ".sol"
	}
	return name, nil
}

type solanaSNSProfile struct {
	PrimaryName      *string    `json:"sns_primary_name"`
	ResolutionStatus string     `json:"sns_resolution_status"`
	ResolvedAt       *time.Time `json:"sns_resolved_at"`
	Error            *string    `json:"sns_error"`
}

// SNS resolution is AuthKit-owned and always-on with fixed timeout/cache — there is
// no host toggle or override (the only prerequisite is a Postgres store to read/write).
// solanaSNS holds the SNS-resolution state the resolver does not own: the
// cache TTL, fixed in production and settable by tests to force staleness,
// and the users whose resolution is running (one background lookup per user).
type solanaSNS struct {
	cacheTTL time.Duration

	mu       sync.Mutex
	inflight map[string]bool
}

func (c *solanaSNS) ttl() time.Duration {
	if c.cacheTTL > 0 {
		return c.cacheTTL
	}
	return defaultSolanaSNSCacheTTL
}

func (s *Engine) solanaSNSCacheTTL() time.Duration {
	if s == nil {
		return defaultSolanaSNSCacheTTL
	}
	return s.sns.ttl()
}

func normalizeSolanaSNSName(name string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "", nil
	}
	if !strings.HasSuffix(normalized, ".sol") || strings.ContainsAny(normalized, " \t\r\n") {
		return "", errors.New(solanaSNSInvalidNameError)
	}
	return normalized, nil
}

// maybeResolveSolanaSNSAfterLink refreshes SNS metadata in the background so
// a slow or unavailable resolver never delays the link or login that
// triggered it. Concurrent triggers for one user coalesce.
func (s *Engine) maybeResolveSolanaSNSAfterLink(ctx context.Context, userID, address string) {
	if s.pg == nil {
		return
	}
	s.sns.mu.Lock()
	if s.sns.inflight[userID] {
		s.sns.mu.Unlock()
		return
	}
	if s.sns.inflight == nil {
		s.sns.inflight = map[string]bool{}
	}
	s.sns.inflight[userID] = true
	s.sns.mu.Unlock()
	go func() {
		defer func() {
			s.sns.mu.Lock()
			delete(s.sns.inflight, userID)
			s.sns.mu.Unlock()
		}()
		_, _ = s.resolveAndStoreSolanaSNS(context.WithoutCancel(ctx), userID, address)
	}()
}

// resolveAndStoreSolanaSNS refreshes cached SNS metadata for an existing SIWS link.
// Resolver failures are recorded as stable metadata and do not invalidate the wallet link.
func (s *Engine) resolveAndStoreSolanaSNS(ctx context.Context, userID, address string) (authflow.SolanaLinkedAccount, error) {
	account := authflow.SolanaLinkedAccount{
		Provider:            solanaProviderSlug,
		Issuer:              s.solanaIssuer(),
		Address:             address,
		Verified:            true,
		SNSResolutionStatus: solanaSNSStatusPending,
	}
	if s.pg == nil {
		return account, nil
	}

	resolveCtx, cancel := context.WithTimeout(ctx, defaultSolanaSNSLookupTimeout)
	defer cancel()

	status := solanaSNSStatusResolved
	var primaryName *string
	var errorCode *string
	name, err := s.solanaSNSResolver.ResolvePrimaryName(resolveCtx, address)
	if err != nil {
		status = solanaSNSStatusError
		code := solanaSNSProviderError
		errorCode = &code
	} else {
		normalized, normalizeErr := normalizeSolanaSNSName(name)
		if normalizeErr != nil {
			status = solanaSNSStatusError
			code := solanaSNSInvalidNameError
			errorCode = &code
		} else if normalized == "" {
			status = solanaSNSStatusNotFound
		} else {
			primaryName = &normalized
		}
	}

	now := time.Now().UTC()
	account.PrimarySNSName = primaryName
	account.SNSResolutionStatus = status
	account.SNSResolvedAt = &now
	account.SNSError = errorCode

	profile := solanaSNSProfile{
		PrimaryName:      primaryName,
		ResolutionStatus: status,
		ResolvedAt:       &now,
		Error:            errorCode,
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return account, err
	}
	err = s.q.UserProviderMergeProfile(ctx, db.UserProviderMergeProfileParams{UserID: userID, Issuer: s.solanaIssuer(), Subject: address, Patch: body})
	return account, err
}

// GetSolanaLinkedAccount retrieves the SIWS-linked wallet and its AuthKit-owned metadata.
func (s *Engine) GetSolanaLinkedAccount(ctx context.Context, userID string) (*authflow.SolanaLinkedAccount, error) {
	if s.pg == nil {
		return nil, nil
	}

	row, err := s.q.UserProviderSubjectProfileByIssuer(ctx, db.UserProviderSubjectProfileByIssuerParams{UserID: userID, Issuer: s.solanaIssuer()})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	address := row.Subject

	var profile solanaSNSProfile
	if strings.TrimSpace(row.Profile) != "" {
		_ = json.Unmarshal([]byte(row.Profile), &profile)
	}

	if row.VerifiedAt == nil {
		return &authflow.SolanaLinkedAccount{
			Provider:            solanaProviderSlug,
			Issuer:              s.solanaIssuer(),
			Address:             address,
			Verified:            false,
			VerifiedAt:          nil,
			SNSResolutionStatus: solanaSNSStatusPending,
		}, nil
	}

	verifiedAt := row.VerifiedAt.UTC()
	status := strings.TrimSpace(profile.ResolutionStatus)
	if status == "" {
		status = solanaSNSStatusPending
	}

	stale := false
	if profile.ResolvedAt == nil {
		stale = true
	} else if time.Since(profile.ResolvedAt.UTC()) > s.solanaSNSCacheTTL() {
		stale = true
	}
	if stale {
		status = solanaSNSStatusStale
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, address)
	}

	return &authflow.SolanaLinkedAccount{
		Provider:            solanaProviderSlug,
		Issuer:              s.solanaIssuer(),
		Address:             address,
		Verified:            true,
		VerifiedAt:          &verifiedAt,
		PrimarySNSName:      profile.PrimaryName,
		SNSResolutionStatus: status,
		SNSResolvedAt:       profile.ResolvedAt,
		SNSStale:            stale,
		SNSError:            profile.Error,
	}, nil
}
