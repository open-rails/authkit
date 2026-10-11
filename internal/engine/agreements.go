package engine

// Agreements (#449): the documents users accept (Config.Agreements), each
// acceptance an append-only row of user_agreements. A self-registration
// accepts Registration.Agreements at their current versions in the
// transaction that creates the account; an OAuth client's approval needs its
// client's; everything else is the host's to gate on (Client.UserAgreements).

import (
	"context"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
)

// agreement is the declared document key names.
func (s *Engine) agreement(key string) (config.AgreementConfig, bool) {
	for _, a := range s.cfg.Agreements {
		if a.Key == key {
			return a, true
		}
	}
	return config.AgreementConfig{}, false
}

// Agreements are the declared documents at their current versions.
func (s *Engine) Agreements() []iam.Agreement {
	out := make([]iam.Agreement, 0, len(s.cfg.Agreements))
	for _, a := range s.cfg.Agreements {
		out = append(out, iam.Agreement{Key: a.Key, Version: a.Version, URL: a.URL})
	}
	return out
}

// RegistrationAgreements are the keys every self-registration accepts.
func (s *Engine) RegistrationAgreements() []string {
	return slices.Clone(s.cfg.Registration.Agreements)
}

// agreementRequired is agreement_required naming docs.
func agreementRequired(docs []config.AgreementConfig) error {
	meta := errmodel.AgreementsRequired{Agreements: make([]errmodel.AgreementDocument, 0, len(docs))}
	for _, a := range docs {
		meta.Agreements = append(meta.Agreements, errmodel.AgreementDocument{Key: a.Key, Version: a.Version, URL: a.URL})
	}
	return errmodel.E(errmodel.CodeAgreementRequired, errmodel.WithDetails(meta))
}

// missingAgreements are the documents among keys whose current version
// accepted does not name.
func (s *Engine) missingAgreements(keys []string, accepted []iam.AgreementRef) []config.AgreementConfig {
	var out []config.AgreementConfig
	for _, key := range keys {
		a, ok := s.agreement(key)
		if !ok {
			continue
		}
		if !slices.Contains(accepted, iam.AgreementRef{Key: a.Key, Version: a.Version}) {
			out = append(out, a)
		}
	}
	return out
}

// requireRegistrationAgreements refuses a sign-up that does not accept every
// Registration.Agreements document at its current version.
func (s *Engine) requireRegistrationAgreements(accepted []iam.AgreementRef) error {
	if missing := s.missingAgreements(s.cfg.Registration.Agreements, accepted); len(missing) > 0 {
		return agreementRequired(missing)
	}
	return nil
}

// acceptable checks refs name declared documents at their current versions,
// trimmed and without repeats: an earlier version is agreement_required for
// the current one, an unknown key invalid_request.
func (s *Engine) acceptable(refs []iam.AgreementRef) ([]iam.AgreementRef, error) {
	out := make([]iam.AgreementRef, 0, len(refs))
	var stale []config.AgreementConfig
	for _, r := range refs {
		r.Key, r.Version = strings.TrimSpace(r.Key), strings.TrimSpace(r.Version)
		a, ok := s.agreement(r.Key)
		switch {
		case !ok:
			return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("agreements"))
		case r.Version != a.Version:
			stale = append(stale, a)
		case !slices.Contains(out, r):
			out = append(out, r)
		}
	}
	if len(stale) > 0 {
		return nil, agreementRequired(stale)
	}
	return out, nil
}

// agreementInput is one acceptance's record: who, where and from what client.
type agreementInput struct {
	Channel   iam.AgreementChannel
	IP        string
	UserAgent string
}

// recordAgreements records userID's acceptance of refs, already checked
// acceptable, in q's transaction.
func recordAgreements(ctx context.Context, q *db.Queries, userID string, refs []iam.AgreementRef, in agreementInput) error {
	for _, r := range refs {
		if err := q.UserAgreementInsert(ctx, db.UserAgreementInsertParams{
			UserID: userID, Key: r.Key, Version: r.Version, Channel: string(in.Channel),
			IpAddr: nullable(in.IP), UserAgent: nullable(truncate(in.UserAgent, 512)),
		}); err != nil {
			return err
		}
	}
	return nil
}

// AcceptAgreements records userID's acceptance of refs, each a declared
// document at its current version.
func (s *Engine) AcceptAgreements(ctx context.Context, userID string, refs []iam.AgreementRef, opts ...ops.Option) error {
	if err := noOptions("AcceptAgreements", opts); err != nil {
		return err
	}
	return s.RecordAgreements(ctx, userID, refs, iam.AgreementByHost, "", "")
}

// RecordAgreements is AcceptAgreements on channel, with the client that gave
// it.
func (s *Engine) RecordAgreements(ctx context.Context, userID string, refs []iam.AgreementRef, channel iam.AgreementChannel, ip, userAgent string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return iam.ErrUserNotFound
	}
	refs, err := s.acceptable(refs)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("agreements"))
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if u, err := q.UserCredentialVersionForUpdate(ctx, userID); err != nil || u.DeletedAt != nil {
		return iam.ErrUserNotFound
	}
	if err := recordAgreements(ctx, q, userID, refs, agreementInput{Channel: channel, IP: ip, UserAgent: userAgent}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UserAgreements returns userID's acceptances, every version, by key.
func (s *Engine) UserAgreements(ctx context.Context, userID string) ([]iam.AgreementAcceptance, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return nil, iam.ErrUserNotFound
	}
	rows, err := s.q.UserAgreementsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]iam.AgreementAcceptance, 0, len(rows))
	for _, r := range rows {
		out = append(out, iam.AgreementAcceptance{Key: r.Key, Version: r.Version, AcceptedAt: r.AcceptedAt.UTC(), Channel: iam.AgreementChannel(r.Channel)})
	}
	return out, nil
}

// AgreementsDue are the documents userID is asked to accept now: one
// Registration.Agreements names that the account never accepted (created
// before it was required, or by the host), and one marked Reaccept whose
// earlier version it accepted.
func (s *Engine) AgreementsDue(ctx context.Context, userID string) ([]iam.Agreement, error) {
	out := []iam.Agreement{}
	if len(s.cfg.Agreements) == 0 {
		return out, nil
	}
	accepted, err := s.UserAgreements(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, a := range s.cfg.Agreements {
		current, earlier := false, false
		for _, acc := range accepted {
			if acc.Key == a.Key {
				current = current || acc.Version == a.Version
				earlier = earlier || acc.Version != a.Version
			}
		}
		if !current && (earlier && a.Reaccept || !earlier && slices.Contains(s.cfg.Registration.Agreements, a.Key)) {
			out = append(out, iam.Agreement{Key: a.Key, Version: a.Version, URL: a.URL})
		}
	}
	return out, nil
}

// requireAcceptedAgreements refuses userID until it has accepted the current
// version of each of keys: an OAuth client's agreements before approval.
func (s *Engine) requireAcceptedAgreements(ctx context.Context, userID string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	accepted, err := s.UserAgreements(ctx, userID)
	if err != nil {
		return err
	}
	refs := make([]iam.AgreementRef, 0, len(accepted))
	for _, a := range accepted {
		refs = append(refs, iam.AgreementRef{Key: a.Key, Version: a.Version})
	}
	if missing := s.missingAgreements(keys, refs); len(missing) > 0 {
		return agreementRequired(missing)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
