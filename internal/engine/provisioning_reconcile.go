package engine

import (
	"context"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/scim"
)

const (
	// reconcilePage is how many users one list request asks the target for.
	reconcilePage = 200
	// unseenBatch is how many unlisted resources one query reads.
	unseenBatch = 100
)

// reconcile compares the target's users with the accounts and queues every
// account whose resource drifted, is missing, or belongs to a purged
// account. It spans runs: it lists the target's users page by page, saving
// the next startIndex with each page, then asks for each resource the
// listing did not show (a page shifted by a change, or a resource the target
// lost) by its id. A run that stops, at its budget or a failure, leaves the
// rest to the next. A resource whose externalId names no account and no
// resource AuthKit made is not AuthKit's, and is left alone.
func (r *provisioningRun) reconcile(ctx context.Context, row db.ProvisioningTarget) error {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	asOf, next := row.ReconcileStartedAt, 1
	if asOf == nil {
		started := s.nowTime()
		asOf = &started
		if err := s.q.ProvisioningReconcileBegin(ctx, db.ProvisioningReconcileBeginParams{Issuer: issuer, Name: name, AsOf: asOf}); err != nil {
			return err
		}
	} else if row.ReconcileNextIndex != nil {
		next = int(*row.ReconcileNextIndex)
	}
	if row.ReconcileStartedAt == nil || row.ReconcileListedAt == nil {
		done, err := r.listTarget(ctx, next)
		if err != nil || !done {
			return err
		}
	}
	for {
		unseen, err := s.q.ProvisioningUnseen(ctx, db.ProvisioningUnseenParams{Issuer: issuer, Target: name, AsOf: asOf, MaxRows: unseenBatch})
		if err != nil {
			return err
		}
		if len(unseen) == 0 {
			break
		}
		for _, res := range unseen {
			if !s.nowTime().Before(r.deadline) {
				return nil
			}
			if err := r.checkUnseen(ctx, res); err != nil {
				return err
			}
		}
	}
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		q := s.qtx(tx)
		if err := q.ProvisioningReconcileUnlinked(ctx, db.ProvisioningReconcileUnlinkedParams{Issuer: issuer, Target: name}); err != nil {
			return err
		}
		return q.ProvisioningReconciled(ctx, db.ProvisioningReconciledParams{Issuer: issuer, Name: name, AsOf: asOf})
	})
}

// listTarget lists the target's users from startIndex next, comparing each
// page and saving the next index with it; done once the listing is through.
func (r *provisioningRun) listTarget(ctx context.Context, next int) (done bool, err error) {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	spc, err := r.config(ctx)
	if err != nil {
		return false, err
	}
	count := reconcilePage
	if m := spc.Filter.MaxResults; m > 0 && m < count {
		count = m
	}
	for {
		if !s.nowTime().Before(r.deadline) {
			return false, nil
		}
		page, err := r.target.client.List(ctx, next, count)
		if err != nil {
			return false, unreachable(err)
		}
		next += len(page.Resources)
		through := len(page.Resources) == 0 || next > page.TotalResults
		index := int32(next)
		err = pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
			q := s.qtx(tx)
			if err := r.compare(ctx, q, page.Resources); err != nil {
				return err
			}
			if through {
				return q.ProvisioningReconcileListed(ctx, db.ProvisioningReconcileListedParams{Issuer: issuer, Name: name})
			}
			return q.ProvisioningReconcileAdvance(ctx, db.ProvisioningReconcileAdvanceParams{Issuer: issuer, Name: name, NextIndex: &index})
		})
		if err != nil || through {
			return through, err
		}
	}
}

// checkUnseen asks the target for a resource its listing did not show: one
// it no longer holds is created again; one it holds is compared.
func (r *provisioningRun) checkUnseen(ctx context.Context, res db.ProvisioningUnseenRow) error {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	theirs, err := r.target.client.Get(ctx, res.RemoteID)
	if scim.IsStatus(err, http.StatusNotFound) {
		return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
			q := s.qtx(tx)
			if err := q.ProvisioningResourceDelete(ctx, db.ProvisioningResourceDeleteParams{Issuer: issuer, Target: name, UserID: res.UserID}); err != nil {
				return err
			}
			return q.ProvisioningEnqueue(ctx, db.ProvisioningEnqueueParams{Issuer: issuer, Target: name, Users: []string{res.UserID}})
		})
	}
	if err != nil {
		return unreachable(err)
	}
	theirs.ID, theirs.ExternalID = res.RemoteID, res.UserID
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error { return r.compare(ctx, s.qtx(tx), []scim.User{theirs}) })
}

// compare records the target's users as seen and queues the accounts whose
// resource drifted.
func (r *provisioningRun) compare(ctx context.Context, q *db.Queries, remote []scim.User) error {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	byUser := map[string]scim.User{}
	for _, u := range remote {
		if id, ok := canonicalUUID(u.ExternalID); ok && u.ID != "" {
			byUser[id] = u
		}
	}
	if len(byUser) == 0 {
		return nil
	}
	ids := make([]string, 0, len(byUser))
	for id := range byUser {
		ids = append(ids, id)
	}
	accounts, err := q.UsersByIDs(ctx, ids)
	if err != nil {
		return err
	}
	resources, err := q.ProvisioningResources(ctx, db.ProvisioningResourcesParams{Issuer: issuer, Target: name, Users: ids})
	if err != nil {
		return err
	}
	local := make(map[string]db.User, len(accounts))
	for _, u := range accounts {
		local[u.ID] = u
	}
	held := make(map[string]db.ProvisioningResource, len(resources))
	for _, res := range resources {
		held[res.UserID] = res
	}
	asOf := s.nowTime()
	var seenUsers, seenRemote, seenDigest, queue []string
	for id, theirs := range byUser {
		u, exists := local[id]
		res, holds := held[id]
		if !exists && !holds {
			continue
		}
		drifted := !exists || drift(scimUser(u, asOf), theirs) || !holds || res.RemoteID != theirs.ID
		digest := res.StateDigest
		if drifted {
			digest = ""
			queue = append(queue, id)
		}
		seenUsers, seenRemote, seenDigest = append(seenUsers, id), append(seenRemote, theirs.ID), append(seenDigest, digest)
	}
	if len(seenUsers) == 0 {
		return nil
	}
	if err := q.ProvisioningResourcesSeen(ctx, db.ProvisioningResourcesSeenParams{
		Issuer: issuer, Target: name, Users: seenUsers, RemoteIds: seenRemote, Digests: seenDigest, AsOf: asOf,
	}); err != nil {
		return err
	}
	if len(queue) == 0 {
		return nil
	}
	return q.ProvisioningEnqueue(ctx, db.ProvisioningEnqueueParams{Issuer: issuer, Target: name, Users: queue})
}

// drift reports whether theirs differs from ours in what the target shows:
// the username and primary email (without regard to case, as SCIM compares
// them), active, and the display name when the target keeps one.
func drift(ours, theirs scim.User) bool {
	switch {
	case !strings.EqualFold(ours.UserName, theirs.UserName),
		!strings.EqualFold(ours.PrimaryEmail(), theirs.PrimaryEmail()),
		theirs.Active != nil && *theirs.Active != *ours.Active,
		theirs.DisplayName != "" && theirs.DisplayName != ours.DisplayName,
		theirs.Name != nil && theirs.Name.Formatted != "" && (ours.Name == nil || theirs.Name.Formatted != ours.Name.Formatted):
		return true
	}
	return false
}
