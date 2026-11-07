package engine

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
)

func (s *Engine) ImportSessionEvents(ctx context.Context, rows []iam.ImportSessionEvent, opts ...ops.Option) (iam.ImportSessionEventsResult, error) {
	out := iam.ImportSessionEventsResult{Rows: []iam.ImportSessionEventRow{}}
	if err := noOptions("ImportSessionEvents", opts); err != nil {
		return out, err
	}
	if len(rows) > importUsersChunkSize {
		return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithCause(fmt.Errorf("at most %d session events per import", importUsersChunkSize)))
	}
	if len(rows) == 0 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	tenant, err := s.tenantID(ctx)
	if err != nil {
		return out, err
	}
	now := time.Now().UTC()
	cutoff := now.Add(-s.cfg.SessionEventRetention)
	for i, in := range rows {
		row := iam.ImportSessionEventRow{Index: i, Status: iam.SessionEventRefused}
		if in.Issuer == "" {
			in.Issuer = s.cfg.Token.Issuer
		}
		userID, validID := canonicalUUID(in.UserID)
		if !validID || !validImportedSessionEvent(in, now) {
			row.Reason = iam.SessionEventInvalid
		} else if s.cfg.SessionEventRetention >= 0 && in.OccurredAt.Before(cutoff) {
			row.Reason = iam.SessionEventTooOld
		} else {
			outcome, err := s.q.SessionEventImport(ctx, db.SessionEventImportParams{
				TenantID: tenant.String(), UserID: userID, ImportID: in.ID,
				OccurredAt: in.OccurredAt.UTC(), Issuer: in.Issuer, Event: string(in.Kind),
				Method: nullable(in.Method), Reason: nullable(in.Reason),
				IpAddr: nullable(in.IP), UserAgent: nullable(in.UserAgent),
			})
			if err != nil {
				return out, fmt.Errorf("import session event at index %d: %w", i, err)
			}
			switch outcome {
			case "imported":
				row.Status = iam.SessionEventImported
			case "duplicate":
				row.Status = iam.SessionEventDuplicate
			default:
				row.Reason = iam.ImportSessionEventReason(outcome)
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

func validImportedSessionEvent(in iam.ImportSessionEvent, now time.Time) bool {
	if in.Kind != iam.SessionEventCreated && in.Kind != iam.SessionEventFailed {
		return false
	}
	if in.OccurredAt.IsZero() || in.OccurredAt.Year() < 1 || in.OccurredAt.After(now) {
		return false
	}
	if strings.TrimSpace(in.ID) == "" || strings.TrimSpace(in.Issuer) == "" ||
		(strings.TrimSpace(in.Method) == "" && strings.TrimSpace(in.Reason) == "") {
		return false
	}
	for _, field := range []struct {
		text string
		max  int
	}{{in.ID, 256}, {in.Issuer, 2048}, {in.Method, 256}, {in.Reason, 256}, {in.UserAgent, 4096}} {
		if len(field.text) > field.max || !utf8.ValidString(field.text) || strings.ContainsRune(field.text, 0) {
			return false
		}
	}
	if in.IP != "" {
		if len(in.IP) > 45 {
			return false
		}
		ip, err := netip.ParseAddr(in.IP)
		if err != nil || ip.Zone() != "" {
			return false
		}
	}
	return true
}
