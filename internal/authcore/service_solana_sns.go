package authcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

const (
	defaultSolanaSNSLookupTimeout = 3 * time.Second
	defaultSolanaSNSCacheTTL      = 24 * time.Hour

	SolanaSNSStatusDisabled = "disabled"
	SolanaSNSStatusPending  = "pending"
	SolanaSNSStatusResolved = "resolved"
	SolanaSNSStatusNotFound = "not_found"
	SolanaSNSStatusError    = "error"
	SolanaSNSStatusStale    = "stale"

	solanaSNSProviderError     = "resolver_error"
	solanaSNSInvalidNameError  = "invalid_sns_name"
	solanaSNSProfilePrimaryKey = "sns_primary_name"
)

var defaultSolanaSNSProxyURL = "https://sdk-proxy.sns.id"

type defaultSolanaSNSResolver struct {
	client  *http.Client
	baseURL string
}

func newDefaultSolanaSNSResolver() defaultSolanaSNSResolver {
	return defaultSolanaSNSResolver{
		client:  http.DefaultClient,
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
	client := r.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
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

// SolanaLinkedAccount is the AuthKit-owned normalized metadata for a SIWS-linked wallet.
type SolanaLinkedAccount struct {
	Provider            string     `json:"provider"`
	Issuer              string     `json:"issuer"`
	Address             string     `json:"address"`
	Verified            bool       `json:"verified"`
	VerifiedAt          *time.Time `json:"verified_at"`
	PrimarySNSName      *string    `json:"primary_sns_name"`
	SNSResolutionStatus string     `json:"sns_resolution_status"`
	SNSResolvedAt       *time.Time `json:"sns_resolved_at"`
	SNSStale            bool       `json:"sns_stale"`
	SNSError            *string    `json:"sns_error"`
}

type solanaSNSProfile struct {
	PrimaryName      *string    `json:"sns_primary_name"`
	ResolutionStatus string     `json:"sns_resolution_status"`
	ResolvedAt       *time.Time `json:"sns_resolved_at"`
	Error            *string    `json:"sns_error"`
}

func (s *Service) solanaSNSEnabled() bool {
	return s != nil && s.opts.SolanaSNSEnabled
}

func (s *Service) solanaSNSLookupTimeout() time.Duration {
	if s != nil && s.opts.SolanaSNSLookupTimeout > 0 {
		return s.opts.SolanaSNSLookupTimeout
	}
	return defaultSolanaSNSLookupTimeout
}

func (s *Service) solanaSNSCacheTTL() time.Duration {
	if s != nil && s.opts.SolanaSNSCacheTTL > 0 {
		return s.opts.SolanaSNSCacheTTL
	}
	return defaultSolanaSNSCacheTTL
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

func (s *Service) maybeResolveSolanaSNSAfterLink(ctx context.Context, userID, address string) {
	if !s.solanaSNSEnabled() || s.pg == nil {
		return
	}
	_, _ = s.ResolveAndStoreSolanaSNS(ctx, userID, address)
}

// ResolveAndStoreSolanaSNS refreshes cached SNS metadata for an existing SIWS link.
// Resolver failures are recorded as stable metadata and do not invalidate the wallet link.
func (s *Service) ResolveAndStoreSolanaSNS(ctx context.Context, userID, address string) (SolanaLinkedAccount, error) {
	account := SolanaLinkedAccount{
		Provider:            SolanaProviderSlug,
		Issuer:              s.solanaIssuer(),
		Address:             address,
		Verified:            true,
		SNSResolutionStatus: SolanaSNSStatusDisabled,
	}
	if s.pg == nil {
		return account, nil
	}
	if !s.solanaSNSEnabled() {
		return account, nil
	}

	resolveCtx, cancel := context.WithTimeout(ctx, s.solanaSNSLookupTimeout())
	defer cancel()

	status := SolanaSNSStatusResolved
	var primaryName *string
	var errorCode *string
	name, err := s.solanaSNSResolver.ResolvePrimaryName(resolveCtx, address)
	if err != nil {
		status = SolanaSNSStatusError
		code := solanaSNSProviderError
		errorCode = &code
	} else {
		normalized, normalizeErr := normalizeSolanaSNSName(name)
		if normalizeErr != nil {
			status = SolanaSNSStatusError
			code := solanaSNSInvalidNameError
			errorCode = &code
		} else if normalized == "" {
			status = SolanaSNSStatusNotFound
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
func (s *Service) GetSolanaLinkedAccount(ctx context.Context, userID string) (*SolanaLinkedAccount, error) {
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

	verifiedAt := row.CreatedAt.UTC()
	status := strings.TrimSpace(profile.ResolutionStatus)
	if !s.solanaSNSEnabled() {
		status = SolanaSNSStatusDisabled
	} else if status == "" {
		status = SolanaSNSStatusPending
	}

	stale := false
	if s.solanaSNSEnabled() {
		if profile.ResolvedAt == nil {
			stale = true
		} else if time.Since(profile.ResolvedAt.UTC()) > s.solanaSNSCacheTTL() {
			stale = true
		}
		if stale {
			status = SolanaSNSStatusStale
			go func() {
				_, _ = s.ResolveAndStoreSolanaSNS(context.Background(), userID, address)
			}()
		}
	}

	return &SolanaLinkedAccount{
		Provider:            SolanaProviderSlug,
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
