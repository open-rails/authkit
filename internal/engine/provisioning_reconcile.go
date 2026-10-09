package engine

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/scim"
)

// reconcilePage is how many users one list request asks the target for.
const reconcilePage = 200

// reconcile lists the target's users and queues every account whose
// resource drifted, is missing, or belongs to a purged account. A resource
// whose externalId names no account and no resource AuthKit made is not
// AuthKit's, and is left alone. An unfinished walk records nothing; the
// next run starts over.
func (r *provisioningRun) reconcile(ctx context.Context) error {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	asOf := s.nowTime()
	count := reconcilePage
	if m := r.spc.Filter.MaxResults; m > 0 && m < count {
		count = m
	}
	for start := 1; ; {
		if !s.nowTime().Before(r.deadline) {
			return nil
		}
		page, err := r.target.client.List(ctx, start, count)
		if err != nil {
			return unreachable(err)
		}
		if err := r.reconcilePage(ctx, page.Resources); err != nil {
			return err
		}
		start += len(page.Resources)
		if len(page.Resources) == 0 || start > page.TotalResults {
			break
		}
	}
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		q := s.qtx(tx)
		if err := q.ProvisioningReconcileMissing(ctx, db.ProvisioningReconcileMissingParams{Issuer: issuer, Target: name, AsOf: &asOf}); err != nil {
			return err
		}
		if err := q.ProvisioningReconcileUnlinked(ctx, db.ProvisioningReconcileUnlinkedParams{Issuer: issuer, Target: name}); err != nil {
			return err
		}
		return q.ProvisioningReconciled(ctx, db.ProvisioningReconciledParams{Issuer: issuer, Name: name, AsOf: &asOf})
	})
}

func (r *provisioningRun) reconcilePage(ctx context.Context, remote []scim.User) error {
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
	accounts, err := s.q.UsersByIDs(ctx, ids)
	if err != nil {
		return err
	}
	resources, err := s.q.ProvisioningResources(ctx, db.ProvisioningResourcesParams{Issuer: issuer, Target: name, Users: ids})
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
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		q := s.qtx(tx)
		if err := q.ProvisioningResourcesSeen(ctx, db.ProvisioningResourcesSeenParams{
			Issuer: issuer, Target: name, Users: seenUsers, RemoteIds: seenRemote, Digests: seenDigest, AsOf: asOf,
		}); err != nil {
			return err
		}
		if len(queue) == 0 {
			return nil
		}
		return q.ProvisioningEnqueue(ctx, db.ProvisioningEnqueueParams{Issuer: issuer, Target: name, Users: queue})
	})
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
		theirs.Name != nil && theirs.Name.Formatted != "" && theirs.Name.Formatted != ours.Name.Formatted:
		return true
	}
	return false
}
