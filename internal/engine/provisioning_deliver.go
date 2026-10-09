package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/scim"
)

// Bulk limits when a target advertises none.
const (
	defaultBulkOperations = 100
	defaultBulkPayload    = 1 << 20
	// maxProvisioningRounds is how often one run sends a user again after
	// the target answered that it holds it already, or no longer does.
	maxProvisioningRounds = 3
)

// targetError is a target that could not be reached, or refused a whole
// request: the run stops, and nothing it did not send is consumed.
type targetError struct{ err error }

func (e *targetError) Error() string { return e.err.Error() }

// unreachable wraps err as a targetError when it says the target as a whole
// failed: a transport error, or a status that is not about one user.
func unreachable(err error) error {
	var se *scim.StatusError
	if errors.As(err, &se) && !targetWide(se.Status) {
		return err
	}
	return &targetError{err}
}

func targetWide(status int) bool {
	return status >= 500 || status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests
}

type provisioningRun struct {
	engine   *Engine
	target   *provisioningTarget
	spc      scim.ServiceProviderConfig
	deadline time.Time
	// rounds counts each user's sends after a conflict or a lost resource.
	rounds map[string]int
	// noBulk: the target advertised bulk but has no /Bulk.
	noBulk bool
	// lastError is the latest refusal of one user's state; "" when the run
	// had none.
	lastError string
}

type provisioningMethod int

const (
	provisionNothing provisioningMethod = iota
	provisionCreate
	provisionReplace
	provisionDelete
)

// provisioningOp is one user's latest state for the target.
type provisioningOp struct {
	userID   string
	through  int64
	method   provisioningMethod
	remoteID string
	resource scim.User
	digest   string
	// banEnds is when a temporary ban in force ends: active changes then.
	banEnds *time.Time
}

// provisioningResult is what the target did with one op.
type provisioningResult struct {
	op       *provisioningOp
	accepted bool
	remoteID string
	// conflict: a create found the user there; gone: a replace found it gone.
	conflict, gone bool
	err            error
}

// deliver sends batches until no change is due (caughtUp) or the run's
// budget is spent.
func (r *provisioningRun) deliver(ctx context.Context) (caughtUp bool, err error) {
	for r.engine.nowTime().Before(r.deadline) {
		n, err := r.batch(ctx)
		if err != nil || n == 0 {
			return err == nil, err
		}
	}
	return false, nil
}

// batch sends the oldest due users' latest state and returns how many it
// read.
func (r *provisioningRun) batch(ctx context.Context) (int, error) {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	asOf := s.nowTime()
	window, err := s.q.ProvisioningDueWindow(ctx, db.ProvisioningDueWindowParams{Issuer: issuer, Target: name, AsOf: asOf, MaxRows: provisioningWindow})
	if err != nil || len(window) == 0 {
		return 0, err
	}
	users := dedup(window)
	through, err := s.q.ProvisioningPendingThrough(ctx, db.ProvisioningPendingThroughParams{Issuer: issuer, Target: name, Users: users, AsOf: asOf})
	if err != nil {
		return 0, err
	}
	accounts, err := s.q.UsersByIDs(ctx, users)
	if err != nil {
		return 0, err
	}
	resources, err := s.q.ProvisioningResources(ctx, db.ProvisioningResourcesParams{Issuer: issuer, Target: name, Users: users})
	if err != nil {
		return 0, err
	}
	byID := make(map[string]db.User, len(accounts))
	for _, u := range accounts {
		byID[u.ID] = u
	}
	held := make(map[string]db.ProvisioningResource, len(resources))
	for _, res := range resources {
		held[res.UserID] = res
	}
	ops := make([]*provisioningOp, 0, len(through))
	for _, p := range through {
		op := &provisioningOp{userID: p.UserID, through: p.Through}
		res, holds := held[p.UserID]
		u, exists := byID[p.UserID]
		switch {
		case !exists && holds:
			op.method, op.remoteID = provisionDelete, res.RemoteID
		case !exists:
		default:
			op.resource = scimUser(u, asOf)
			op.digest = resourceDigest(op.resource)
			if u.DeletedAt == nil && banInForce(u.BannedAt, u.BannedUntil, asOf) && u.BannedUntil != nil {
				op.banEnds = u.BannedUntil
			}
			switch {
			case !holds:
				op.method = provisionCreate
			case res.StateDigest != op.digest:
				op.method, op.remoteID = provisionReplace, res.RemoteID
			}
		}
		ops = append(ops, op)
	}
	results, err := r.send(ctx, ops)
	if len(results) > 0 {
		if aerr := r.apply(ctx, asOf, results); aerr != nil {
			return 0, errors.Join(err, aerr)
		}
	}
	return len(users), err
}

// send delivers ops in bulk requests within the target's limits, or one
// request per op when it has no bulk. Results cover the ops sent before a
// target-wide failure.
func (r *provisioningRun) send(ctx context.Context, ops []*provisioningOp) ([]provisioningResult, error) {
	var results []provisioningResult
	var pending []*provisioningOp
	for _, op := range ops {
		if op.method == provisionNothing {
			results = append(results, provisioningResult{op: op, accepted: true, remoteID: op.remoteID})
		} else {
			pending = append(pending, op)
		}
	}
	if !r.spc.Bulk.Supported || r.noBulk {
		for _, op := range pending {
			res, err := r.sendOne(ctx, op)
			if err != nil {
				return results, err
			}
			results = append(results, res)
		}
		return results, nil
	}
	maxOps, maxPayload := r.spc.Bulk.MaxOperations, r.spc.Bulk.MaxPayloadSize
	if maxOps <= 0 {
		maxOps = defaultBulkOperations
	}
	if maxPayload <= 0 {
		maxPayload = defaultBulkPayload
	}
	const envelope = 128 // the request's schemas and Operations wrapper
	for len(pending) > 0 {
		var chunk []*provisioningOp
		var bulk []scim.BulkOperation
		size := envelope
		for len(pending) > 0 && len(chunk) < maxOps {
			op := bulkOperation(pending[0], len(chunk))
			b, err := json.Marshal(op)
			if err != nil {
				return results, err
			}
			if len(chunk) > 0 && size+len(b)+1 > maxPayload {
				break
			}
			size += len(b) + 1
			chunk, bulk, pending = append(chunk, pending[0]), append(bulk, op), pending[1:]
		}
		resp, err := r.target.client.Bulk(ctx, bulk)
		if scim.IsStatus(err, http.StatusNotFound) || scim.IsStatus(err, http.StatusNotImplemented) {
			r.noBulk = true // advertised but absent: one request per op from here on
			rest, err := r.send(ctx, append(chunk, pending...))
			return append(results, rest...), err
		}
		if err != nil {
			return results, unreachable(err)
		}
		byBulkID := make(map[string]scim.BulkResult, len(resp.Operations))
		for _, res := range resp.Operations {
			byBulkID[res.BulkID] = res
		}
		for i, op := range chunk {
			res, ok := byBulkID[bulkID(i)]
			if !ok && i < len(resp.Operations) && resp.Operations[i].BulkID == "" {
				res, ok = resp.Operations[i], true // a provider that echoes no bulkId answers in order
			}
			if !ok {
				results = append(results, provisioningResult{op: op, err: errors.New("the bulk response has no result for the operation")})
				continue
			}
			results = append(results, bulkResult(op, res))
		}
	}
	return results, nil
}

func bulkID(i int) string { return "op" + strconv.Itoa(i) }

func bulkOperation(op *provisioningOp, i int) scim.BulkOperation {
	out := scim.BulkOperation{BulkID: bulkID(i)}
	switch op.method {
	case provisionCreate:
		out.Method, out.Path, out.Data = http.MethodPost, "/Users", op.resource
	case provisionReplace:
		out.Method, out.Path, out.Data = http.MethodPut, "/Users/"+url.PathEscape(op.remoteID), op.resource
	case provisionDelete:
		out.Method, out.Path = http.MethodDelete, "/Users/"+url.PathEscape(op.remoteID)
	}
	return out
}

func bulkResult(op *provisioningOp, res scim.BulkResult) provisioningResult {
	status := int(res.Status)
	out := provisioningResult{op: op, remoteID: op.remoteID}
	switch {
	case status >= 200 && status < 300:
		out.accepted = true
		if op.method == provisionCreate {
			out.remoteID = scim.LocationID(res.Location)
			var created scim.User
			if out.remoteID == "" && json.Unmarshal(res.Response, &created) == nil {
				out.remoteID = created.ID
			}
			if out.remoteID == "" {
				out.accepted, out.err = false, errors.New("the target created the user without a location")
			}
		}
	case op.method == provisionCreate && status == http.StatusConflict:
		out.conflict = true
	case op.method == provisionReplace && status == http.StatusNotFound:
		out.gone = true
	case op.method == provisionDelete && status == http.StatusNotFound:
		out.accepted = true
	default:
		out.err = scim.ErrorOf(status, res.Response)
	}
	return out
}

func (r *provisioningRun) sendOne(ctx context.Context, op *provisioningOp) (provisioningResult, error) {
	c := r.target.client
	out := provisioningResult{op: op, remoteID: op.remoteID}
	var err error
	switch op.method {
	case provisionCreate:
		var created scim.User
		created, err = c.Create(ctx, op.resource)
		out.remoteID = created.ID
		if err == nil && created.ID == "" {
			err = errors.New("the target created the user without an id")
		}
		if scim.IsStatus(err, http.StatusConflict) {
			out.conflict, err = true, nil
		}
	case provisionReplace:
		err = c.Replace(ctx, op.remoteID, op.resource)
		if scim.IsStatus(err, http.StatusNotFound) {
			out.gone, err = true, nil
		}
	case provisionDelete:
		err = c.Delete(ctx, op.remoteID)
	}
	var se *scim.StatusError
	switch {
	case err == nil:
		out.accepted = !out.conflict && !out.gone
	case errors.As(err, &se) && !targetWide(se.Status):
		out.err = err
	default:
		return out, unreachable(err)
	}
	return out, nil
}

// apply records results: accepted users' changes are delivered and what the
// target holds is updated; a user the target already holds is linked and a
// user it lost is unlinked, both sent again; a refusal waits out its
// backoff.
func (r *provisioningRun) apply(ctx context.Context, asOf time.Time, results []provisioningResult) error {
	s, issuer, name := r.engine, r.engine.cfg.Token.Issuer, r.target.name
	// Conflicts resolve before the transaction: they ask the target.
	for i := range results {
		res := &results[i]
		if !res.conflict {
			continue
		}
		found, ok, err := r.target.client.FindByExternalID(ctx, res.op.userID)
		switch {
		case err != nil:
			res.err = fmt.Errorf("the target refused to create the user (conflict), and looking it up failed: %w", err)
		case !ok || found.ID == "":
			res.err = errors.New("the target refused to create the user (conflict) and holds none with its externalId")
		default:
			res.remoteID = found.ID
		}
	}
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		q := s.qtx(tx)
		var users []string
		var throughs []int64
		for _, res := range results {
			op := res.op
			switch {
			case res.accepted:
				users, throughs = append(users, op.userID), append(throughs, op.through)
				switch op.method {
				case provisionDelete:
					if err := q.ProvisioningResourceDelete(ctx, db.ProvisioningResourceDeleteParams{Issuer: issuer, Target: name, UserID: op.userID}); err != nil {
						return err
					}
				case provisionCreate, provisionReplace:
					if err := q.ProvisioningResourceUpsert(ctx, db.ProvisioningResourceUpsertParams{
						Issuer: issuer, Target: name, UserID: op.userID, RemoteID: res.remoteID, StateDigest: op.digest,
					}); err != nil {
						return err
					}
				}
				if op.banEnds != nil {
					if err := q.ProvisioningSchedule(ctx, db.ProvisioningScheduleParams{Issuer: issuer, Target: name, UserID: op.userID, DueAt: *op.banEnds}); err != nil {
						return err
					}
				}
			case (res.conflict || res.gone) && res.err == nil && r.rounds[op.userID] < maxProvisioningRounds:
				// Still due: the run's next batch sends the user again.
				r.rounds[op.userID]++
				var err error
				if res.gone {
					err = q.ProvisioningResourceDelete(ctx, db.ProvisioningResourceDeleteParams{Issuer: issuer, Target: name, UserID: op.userID})
				} else {
					err = q.ProvisioningResourceUpsert(ctx, db.ProvisioningResourceUpsertParams{Issuer: issuer, Target: name, UserID: op.userID, RemoteID: res.remoteID})
				}
				if err != nil {
					return err
				}
			default:
				cause := res.err
				if cause == nil {
					cause = errors.New("the target keeps answering that it holds the user and that it does not")
				}
				msg := fmt.Sprintf("user %s: %v", op.userID, cause)
				r.lastError = msg
				slog.WarnContext(ctx, "authkit: provisioning target refused a user; will retry", "target", name, "user_id", op.userID, "error", cause)
				interval := s.cfg.Provisioning.Interval
				if err := q.ProvisioningRetry(ctx, db.ProvisioningRetryParams{
					Issuer: issuer, Target: name, UserID: op.userID, Through: op.through, AsOf: asOf, LastError: &msg,
					BaseSeconds: interval.Seconds(), MaxSeconds: max(interval, provisioningMaxBackoff).Seconds(),
				}); err != nil {
					return err
				}
			}
		}
		if len(users) == 0 {
			return nil
		}
		return q.ProvisioningAccept(ctx, db.ProvisioningAcceptParams{Issuer: issuer, Target: name, Users: users, Throughs: throughs, AsOf: asOf})
	})
}

// resourceDigest identifies a state the target accepted.
func resourceDigest(u scim.User) string {
	b, _ := json.Marshal(u)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dedup(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
