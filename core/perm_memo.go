package core

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

func dbOrgUserPermissionsParams(orgSlug, userID string) db.OrgUserPermissionsParams {
	return db.OrgUserPermissionsParams{OrgSlug: orgSlug, UserID: userID}
}

// Per-request permission memoization (#95 — CONTRACT: ≤ 1 DB round-trip per
// request per layer).
//
// Without memoization a handler that checks N permissions in one request issues
// N permission-cover queries (one per HasPermission / HasPlatformPermission
// call). This file resolves each (layer, principal[, org]) grant set ONCE — via
// a SINGLE indexed JOIN that materializes the RAW grant tokens — stashes it in a
// REQUEST-SCOPED cache carried on context.Context, and answers every subsequent
// check for the same key IN-MEMORY using the exact glob semantics of permMatches
// (the same `permission = ANY(cover_tokens)` logic OrgUserHasPermissionToken /
// PlatformUserHasPermissionToken run in SQL, now evaluated against the cached
// token set).
//
// The cache is REQUEST-SCOPED ON PURPOSE: a fresh map per request, never a
// process-global cache. Grants must NEVER be stale across requests — instant
// revocation is a hard #95 requirement, perms are never baked into the JWT — so
// every new request re-resolves from the DB on its first check.
//
// Tokens (not the expanded concrete set) are cached so the in-memory match is
// byte-for-byte identical to the SQL path: a glob `org:*` stays ONE entry and is
// matched against the request perm with permMatches, exactly as the cover-token
// `ANY(...)` would have. A non-member / regular-user resolves to an empty token
// set (0 rows), which every check then misses — same allow/deny as today.

// permLayer identifies which RBAC plane a memoized grant set belongs to. The
// two planes are disjoint (#95): an org grant never satisfies a platform check
// and vice-versa, so they are cached under distinct layer keys.
type permLayer string

const (
	permLayerOrg      permLayer = "org"
	permLayerPlatform permLayer = "platform"
)

// permMemoKey is the cache key: layer + principal (+ org slug for the org
// layer; empty for platform). The org slug is the CANONICAL slug AFTER rename
// resolution is folded into the single query, but two requests naming the same
// org via different historical slugs still each resolve once — acceptable, the
// contract is "≤ 1 query per (layer, principal, org)" and a per-slug key keeps
// the cache trivially correct.
type permMemoKey struct {
	layer     permLayer
	principal string
	org       string
}

// permMemo is the request-scoped cache: per key, the RAW grant tokens resolved
// in a single query. A present (possibly empty) entry means "already resolved
// this request — answer in-memory, no further query".
type permMemo struct {
	sets map[permMemoKey][]string
}

type permMemoCtxKey struct{}

// withPermMemo returns a context carrying a fresh, empty request-scoped
// permission cache. The HTTP middleware seeds this once per request; the
// memoized resolvers also seed it lazily (see permMemoFromContext) so a caller
// that forgot to seed still gets per-call correctness (just no cross-call
// sharing). EXPORTED-equivalent entrypoint lives in the http package.
func withPermMemo(ctx context.Context) context.Context {
	if _, ok := ctx.Value(permMemoCtxKey{}).(*permMemo); ok {
		return ctx // already seeded — keep the existing per-request cache
	}
	return context.WithValue(ctx, permMemoCtxKey{}, &permMemo{sets: map[permMemoKey][]string{}})
}

// permMemoFromContext returns the request-scoped cache, or nil when none was
// seeded. A nil cache means "no memoization" — each check resolves directly
// (still correct, just not shared), which is what un-seeded background/internal
// callers get.
func permMemoFromContext(ctx context.Context) *permMemo {
	m, _ := ctx.Value(permMemoCtxKey{}).(*permMemo)
	return m
}

// WithPermissionMemo seeds a fresh request-scoped permission-resolution cache on
// ctx (idempotent — keeps an existing one). The HTTP auth middleware calls this
// once per request so that every gate within the request shares ONE resolution
// per (layer, principal, org). It is safe (and a no-op-ish) to call from tests
// that simulate a single request context.
func WithPermissionMemo(ctx context.Context) context.Context {
	return withPermMemo(ctx)
}

// resolveOrgTokens returns the user's RAW org grant tokens for orgSlug,
// resolving from the request-scoped cache when present and otherwise issuing the
// SINGLE OrgUserPermissions query (one indexed JOIN, rename-aware). On a cache
// hit it performs ZERO queries.
func (s *Service) resolveOrgTokens(ctx context.Context, orgSlug, userID string) ([]string, error) {
	orgSlug = strings.TrimSpace(orgSlug)
	userID = strings.TrimSpace(userID)
	key := permMemoKey{layer: permLayerOrg, principal: userID, org: orgSlug}
	if memo := permMemoFromContext(ctx); memo != nil {
		if toks, ok := memo.sets[key]; ok {
			return toks, nil
		}
		toks, err := s.q.OrgUserPermissions(ctx, dbOrgUserPermissionsParams(orgSlug, userID))
		if err != nil {
			return nil, err
		}
		memo.sets[key] = toks
		return toks, nil
	}
	return s.q.OrgUserPermissions(ctx, dbOrgUserPermissionsParams(orgSlug, userID))
}

// resolvePlatformTokens returns the user's RAW platform grant tokens, from the
// request-scoped cache when present and otherwise via the SINGLE
// PlatformUserPermissions query (one indexed JOIN; a regular user has 0 rows in
// platform_user_roles so the permission table is never touched).
func (s *Service) resolvePlatformTokens(ctx context.Context, userID string) ([]string, error) {
	userID = strings.TrimSpace(userID)
	key := permMemoKey{layer: permLayerPlatform, principal: userID}
	if memo := permMemoFromContext(ctx); memo != nil {
		if toks, ok := memo.sets[key]; ok {
			return toks, nil
		}
		toks, err := s.q.PlatformUserPermissions(ctx, userID)
		if err != nil {
			return nil, err
		}
		memo.sets[key] = toks
		return toks, nil
	}
	return s.q.PlatformUserPermissions(ctx, userID)
}

// tokensCover reports whether any RAW grant token in set authorizes the
// requested CONCRETE permission, using the SAME namespace-anchored glob
// semantics as the SQL cover-token match (permMatches). This is the in-memory
// equivalent of `WHERE p.permission = ANY(cover_tokens(perm))`.
func tokensCover(set []string, perm string) bool {
	perm = strings.TrimSpace(perm)
	if perm == "" {
		return false
	}
	for _, t := range set {
		if permMatches(t, perm) {
			return true
		}
	}
	return false
}
