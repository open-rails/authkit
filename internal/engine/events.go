package engine

// Committed account and group changes are appended once to the retained log.
// Consumers read with their own cursor; AuthKit never registers or invokes them.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

func accountScopedQueue(prefix, schema, issuer string) string {
	digest := sha256.Sum256([]byte(schema + "\x00" + issuer))
	return prefix + hex.EncodeToString(digest[:20])
}

func userEvent(kind iam.EventKind, userID string) iam.Event {
	return iam.Event{Kind: kind, UserID: canonicalID(userID)}
}

// canonicalID is id in the form PostgreSQL returns, when it is a uuid.
func canonicalID(id string) string {
	if canonical, ok := canonicalUUID(id); ok {
		return canonical
	}
	return id
}

func groupEvent(kind iam.EventKind, groupID string, persona iam.Persona) iam.Event {
	return iam.Event{Kind: kind, GroupID: groupID, Persona: persona}
}

// roleEvent is subject's role in the group going from previous to current.
func roleEvent(groupID string, persona iam.Persona, subject iam.Subject, previous, current iam.Role) iam.Event {
	e := iam.Event{Kind: iam.EventRoleChanged, GroupID: groupID, Persona: persona, Previous: previous.String(), Current: current.String()}
	switch {
	case previous.IsZero():
		e.Kind = iam.EventRoleGranted
	case current.IsZero():
		e.Kind = iam.EventRoleRevoked
	}
	if subject.Kind == iam.SubjectKindUser {
		e.UserID = canonicalID(subject.ID)
	} else {
		e.ApplicationID = canonicalID(subject.ID)
	}
	return e
}

// eventIdentity is who made a change, as an event records it: the identity's
// subject, invoker and credential, ids in canonical form.
func eventIdentity(a auth.Identity) iam.Event {
	return iam.Event{
		SubjectKind: a.SubjectKind, SubjectID: canonicalID(a.Subject), InvokerIssuer: a.Invoker.Issuer, InvokerID: canonicalID(a.Invoker.ID),
		CredentialKind: a.Credential.Kind, CredentialID: canonicalID(a.Credential.ID),
	}
}

// accountIdentity is the evented part of an account row.
type accountIdentity struct{ email, phone, username string }

func readAccountIdentity(ctx context.Context, q db.DBTX, userID string) (accountIdentity, error) {
	u, err := db.New(q).UserByID(ctx, userID)
	return accountIdentity{email: deref(u.Email), phone: deref(u.PhoneNumber), username: deref(u.Username)}, err
}

// identityChanges reads the account again and returns the events of what
// changed since before.
func identityChanges(ctx context.Context, q db.DBTX, userID string, before accountIdentity) ([]iam.Event, error) {
	after, err := readAccountIdentity(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	var out []iam.Event
	for _, f := range []struct {
		kind            iam.EventKind
		previous, value string
	}{
		{iam.EventUserEmailChanged, before.email, after.email},
		{iam.EventUserPhoneChanged, before.phone, after.phone},
		{iam.EventUserUsernameChanged, before.username, after.username},
	} {
		if f.previous != f.value {
			out = append(out, iam.Event{Kind: f.kind, UserID: userID, Previous: f.previous, Current: f.value})
		}
	}
	return out, nil
}

// emitEvents snapshots target ownership and actor facts in the transaction
// which changes state, then appends once regardless of whether readers exist.
func (s *Engine) emitEvents(ctx context.Context, q db.DBTX, a auth.Identity, events ...iam.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, ok := q.(pgx.Tx)
	if !ok {
		return errors.New("authkit: events are recorded only in the transaction of their change")
	}
	txq := s.qtx(tx)
	for i := range events {
		tenant, err := s.eventTenant(ctx, txq, events[i])
		if err != nil {
			return err
		}
		events[i].TenantID = tenant
	}
	who := eventIdentity(a)
	for i := range events {
		id, err := newUUIDV7String()
		if err != nil {
			return err
		}
		events[i].ID, events[i].Version, events[i].OccurredAt = id, 1, s.nowTime().UTC()
		events[i].SubjectKind, events[i].SubjectID = who.SubjectKind, who.SubjectID
		events[i].InvokerIssuer, events[i].InvokerID = who.InvokerIssuer, who.InvokerID
		events[i].CredentialKind, events[i].CredentialID = who.CredentialKind, who.CredentialID
	}
	return s.appendEventLog(ctx, tx, events)
}

// fleetProducer is a producer for the River fleet in schema: this runtime's,
// else an insert-only client (no workers, polling or pool of its own) writing
// through the change's transaction.
func (s *Engine) fleetProducer(schema string) (*river.Client[pgx.Tx], error) {
	if m := s.maintenance; m != nil && m.producer.Schema() == schema {
		return m.producer, nil
	}
	if c, ok := s.fleetProducers.Load(schema); ok {
		return c.(*river.Client[pgx.Tx]), nil
	}
	c, err := river.NewClient(riverpgxv5.New(s.pg), riverConfig(schema))
	if err != nil {
		return nil, err
	}
	actual, _ := s.fleetProducers.LoadOrStore(schema, c)
	return actual.(*river.Client[pgx.Tx]), nil
}

// eventTenant snapshots the target owner while it is still available. A root
// operator's source account is never substituted for an affected account.
func (s *Engine) eventTenant(ctx context.Context, q *db.Queries, e iam.Event) (iam.TenantID, error) {
	if e.UserID != "" {
		u, err := q.UserByID(ctx, e.UserID)
		if err == nil {
			return iam.ParseTenantID(u.TenantID)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return iam.TenantID{}, err
		}
		// A final purge emits after DELETE with its retained receipt owner.
		if !e.TenantID.IsZero() {
			return e.TenantID, nil
		}
		return iam.TenantID{}, iam.ErrUserNotFound
	}
	if e.GroupID != "" {
		g, err := q.AuthorityGroupState(ctx, e.GroupID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) && !e.TenantID.IsZero() {
				return e.TenantID, nil
			}
			return iam.TenantID{}, err
		}
		if g.TenantID == nil {
			return iam.TenantID{}, nil
		}
		return iam.ParseTenantID(*g.TenantID)
	}
	if e.ApplicationID != "" {
		a, err := q.RemoteApplicationByID(ctx, e.ApplicationID)
		if err != nil {
			return iam.TenantID{}, err
		}
		g, err := q.AuthorityGroupState(ctx, a.PermissionGroupID)
		if err != nil {
			return iam.TenantID{}, err
		}
		if g.TenantID == nil {
			return iam.TenantID{}, nil
		}
		return iam.ParseTenantID(*g.TenantID)
	}
	return iam.TenantID{}, nil
}
