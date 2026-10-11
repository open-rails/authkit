package engine

// Consent to group OAuth clients (#450, OIDC Core §3.1.2.4): a group's client
// is third-party, so a user's first authorization of it asks, and so does
// each scope it adds; prompt=consent asks again. Withdrawing consent ends the
// client's refresh tokens for the user (checked at each refresh against the
// consent they were issued under), sends its OIDC Back-Channel Logout token
// when it registered an endpoint, and records oauth_consent.revoked.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/helpers/auth"
)

// scopeDescriptions describes scopes on the consent screen: a group-client
// scope by the host's text, OpenID's own by "" (the interface's).
func (s *Engine) scopeDescriptions(scopes []string) []errmodel.ScopeDescription {
	out := make([]errmodel.ScopeDescription, 0, len(scopes))
	for _, scope := range scopes {
		d := errmodel.ScopeDescription{Name: scope}
		if sc, ok := config.FindGroupClientScope(s.cfg.AuthorizationServer, scope); ok {
			d.Description = sc.Description
		}
		out = append(out, d)
	}
	return out
}

// ScopeDescriptions is scopeDescriptions for the HTTP layer.
func (s *Engine) ScopeDescriptions(scopes []string) []errmodel.ScopeDescription {
	return s.scopeDescriptions(scopes)
}

// consentFor settles userID's consent to client for a's scopes: the time it
// was first granted, which the code and its refresh tokens stand on. Scopes
// not yet consented to, or every scope with prompt=consent, are
// consent_required until consented (true), which adds them.
func (s *Engine) consentFor(ctx context.Context, userID string, client authflow.OAuthClient, a authflow.OAuthAuthorization, consented bool) (time.Time, error) {
	current, err := s.q.OAuthConsentByUserClient(ctx, db.OAuthConsentByUserClientParams{UserID: userID, ClientID: client.ID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, err
	}
	var needed []string
	for _, scope := range a.Scopes {
		if slices.Contains(a.Prompt, "consent") || !slices.Contains(current.Scopes, scope) {
			needed = append(needed, scope)
		}
	}
	if len(needed) == 0 {
		return current.GrantedAt, nil
	}
	if !consented {
		return time.Time{}, errmodel.E(errmodel.CodeConsentRequired, errmodel.WithDetails(errmodel.ConsentRequired{Scopes: s.scopeDescriptions(needed)}))
	}
	row, err := s.q.OAuthConsentGrant(ctx, db.OAuthConsentGrantParams{UserID: userID, ClientID: client.ID, Scopes: a.Scopes})
	if err != nil {
		return time.Time{}, err
	}
	s.oauthAudit(ctx, "oauth_consent_granted", userID, map[string]string{"client_id": client.ID, "scopes": strings.Join(row.Scopes, " ")})
	return row.GrantedAt, nil
}

// consentStands reports whether userID's consent to clientID is the one
// granted at grantedAt: withdrawn, or withdrawn and given again, it is not.
func (s *Engine) consentStands(ctx context.Context, userID, clientID string, grantedAt time.Time) (bool, error) {
	row, err := s.q.OAuthConsentByUserClient(ctx, db.OAuthConsentByUserClientParams{UserID: userID, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.GrantedAt.Equal(grantedAt), nil
}

// groupName is the host's name for groupID (Deps.GroupName); nil without
// one.
func (s *Engine) groupName(ctx context.Context, groupID string) *string {
	if s.groupNameHook == nil {
		return nil
	}
	name, err := s.groupNameHook(ctx, groupID)
	if err != nil || strings.TrimSpace(name) == "" {
		return nil
	}
	return &name
}

// GroupName is groupName for the HTTP layer.
func (s *Engine) GroupName(ctx context.Context, groupID string) *string {
	return s.groupName(ctx, groupID)
}

// OAuthConsents lists userID's consents, newest change first.
func (s *Engine) OAuthConsents(ctx context.Context, userID string) ([]iam.OAuthConsent, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return nil, iam.ErrUserNotFound
	}
	rows, err := s.q.OAuthConsentsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]iam.OAuthConsent, 0, len(rows))
	for _, r := range rows {
		out = append(out, iam.OAuthConsent{
			ClientID: r.ClientID, ClientName: r.ClientName, GroupID: r.GroupID, GroupName: s.groupName(ctx, r.GroupID),
			LogoURI: r.LogoUri, ClientURI: r.ClientUri, Scopes: r.Scopes, GrantedAt: r.GrantedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return out, nil
}

// RevokeConsent withdraws userID's consent to clientID as the host
// (OpenRails unlinking a merchant).
func (s *Engine) RevokeConsent(ctx context.Context, userID, clientID string, opts ...ops.Option) error {
	if err := noOptions("RevokeConsent", opts); err != nil {
		return err
	}
	return s.WithdrawConsent(ctx, iam.SystemIdentity(), userID, clientID)
}

// WithdrawConsent withdraws userID's consent to clientID, as who: the
// consent goes, the client's refresh tokens for the user end at their next
// use, its back-channel logout is sent, and oauth_consent.revoked recorded.
func (s *Engine) WithdrawConsent(ctx context.Context, who auth.Identity, userID, clientID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return iam.ErrUserNotFound
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	client, err := q.GroupOAuthClientByID(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrOAuthConsentNotFound
	}
	if err != nil {
		return err
	}
	if _, err := q.OAuthConsentDelete(ctx, db.OAuthConsentDeleteParams{UserID: userID, ClientID: clientID}); errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrOAuthConsentNotFound
	} else if err != nil {
		return err
	}
	e := userEvent(iam.EventOAuthConsentRevoked, userID)
	e.GroupID, e.ClientID = client.PermissionGroupID, clientID
	if err := s.emitEvents(ctx, tx, who, e); err != nil {
		return err
	}
	if uri := deref(client.BackchannelLogoutUri); uri != "" {
		producer, err := s.fleetProducer(s.cfg.Database.RiverSchema)
		if err != nil {
			return err
		}
		args := backchannelLogoutArgs{Schema: s.dbSchema(), Issuer: s.cfg.Token.Issuer, ClientID: clientID, UserID: userID, URI: uri}
		if _, err := producer.InsertTx(ctx, tx, args, &river.InsertOpts{Queue: maintenanceQueue(s.dbSchema()), MaxAttempts: 8}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.oauthAudit(ctx, "oauth_consent_revoked", userID, map[string]string{"client_id": clientID})
	return nil
}

// backchannelLogoutArgs is one OIDC Back-Channel Logout 1.0 delivery.
type backchannelLogoutArgs struct {
	Schema   string `json:"schema"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
	URI      string `json:"uri"`
}

func (backchannelLogoutArgs) Kind() string { return "authkit_backchannel_logout" }

type backchannelLogoutWorker struct {
	river.WorkerDefaults[backchannelLogoutArgs]
	engine *Engine
}

func (w *backchannelLogoutWorker) Timeout(*river.Job[backchannelLogoutArgs]) time.Duration {
	return 30 * time.Second
}

func (w *backchannelLogoutWorker) Work(ctx context.Context, job *river.Job[backchannelLogoutArgs]) error {
	s := w.engine
	if job.Args.Schema != s.dbSchema() || job.Args.Issuer != s.cfg.Token.Issuer {
		return river.JobCancel(errors.New("authkit: back-channel logout routed to another deployment"))
	}
	return s.sendBackchannelLogout(ctx, job.Args)
}

// sendBackchannelLogout posts a logout token (OIDC Back-Channel Logout 1.0
// §2.4) naming the user to the client's endpoint.
func (s *Engine) sendBackchannelLogout(ctx context.Context, a backchannelLogoutArgs) error {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return iam.ErrSigningNotConfigured
	}
	jti, err := newUUIDV7String()
	if err != nil {
		return err
	}
	now := s.nowTime()
	token, err := jose.Sign(ctx, signer, "logout+jwt", map[string]any{
		"iss": s.cfg.Token.Issuer, "aud": a.ClientID, "sub": a.UserID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": jti,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URI, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return river.JobCancel(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := netguard.Client(10*time.Second, s.cfg.Token.AllowPrivateNetworkJWKS).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("authkit: back-channel logout to %s: HTTP %d", a.ClientID, res.StatusCode)
	}
	return nil
}
