package embedded

import (
	"context"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// UsersByIDs resolves many user IDs to slim display projections (username/email)
// in ONE query — the batch read behind "resolve N authors for display" without
// N+1 single fetches. IDs that don't exist are simply absent from the result.
//
// PRIVILEGED: the projection carries Email. For anything rendered to other
// users, call PublicUsersByIDs instead (#268).
//
// This replaces the removed authkit/identity store's batch reads. Mutations are
// NOT exposed here on purpose: username/email writes go through UpdateUsername/
// UpdateEmail, which enforce the rename cooldown + validation that raw table
// writes (the old identity.Store) silently skipped.
func (s *Service) UsersByIDs(ctx context.Context, ids []string) (map[string]authkit.UserRef, error) {
	out := map[string]authkit.UserRef{}
	if s.pg == nil || len(ids) == 0 {
		return out, nil
	}
	q := db.New(db.ForSchema(s.pg, s.dbSchema()))
	rows, err := q.IdentityUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		ref := authkit.UserRef{ID: r.ID}
		if r.Username != nil {
			ref.Username = *r.Username
		}
		if r.Email != nil {
			ref.Email = *r.Email
		}
		out[r.ID] = ref
	}
	return out, nil
}

// PublicUsersByIDs resolves many user IDs to the PUBLIC-safe display projection
// in ONE query (#268): the batch read for "render N comment authors" that is
// safe to nest directly into a response body, because authkit.PublicUserRef has
// no email field at all.
//
// Deleted/banned policy, decided once here so three hosts stop each inventing
// it:
//
//   - A SOFT-DELETED user resolves to a TOMBSTONE — present in the map with
//     Deleted set and every display field blanked. Existing references (a
//     comment, a gallery) therefore still render something stable
//     (PublicUserRef.DisplayName → "user-<id8>") instead of silently
//     disappearing, and a caller cannot accidentally publish a deleted
//     account's old name.
//   - A BANNED user is returned normally. A ban is an ACCESS decision (see
//     UserLivenessByIDs), not a visibility one; suppressing bans here would
//     retroactively rewrite public history and would leak moderation state to
//     anyone who diffed the page.
//   - An id that matches no row at all is ABSENT from the map, like UsersByIDs.
//     authkit.PublicDisplayName covers that case for callers that want one
//     branch-free lookup.
func (s *Service) PublicUsersByIDs(ctx context.Context, ids []string) (map[string]authkit.PublicUserRef, error) {
	out := map[string]authkit.PublicUserRef{}
	if s.pg == nil || len(ids) == 0 {
		return out, nil
	}
	q := db.New(db.ForSchema(s.pg, s.dbSchema()))
	rows, err := q.IdentityPublicUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.DeletedAt != nil {
			// A tombstone carries the id and nothing else: the reference resolves,
			// and no attribute of the deleted account — not even its join date —
			// is published.
			out[r.ID] = authkit.PublicUserRef{ID: r.ID, Deleted: true}
			continue
		}
		ref := authkit.PublicUserRef{ID: r.ID, CreatedAt: r.CreatedAt}
		if r.Username != nil {
			ref.Username = *r.Username
		}
		if r.AvatarUrl != nil {
			ref.AvatarURL = *r.AvatarUrl
		}
		out[r.ID] = ref
	}
	return out, nil
}

// UserLivenessByIDs resolves many user IDs to their account-liveness verdict
// plus fresh identity fields in ONE query (#267) — the read behind verify's
// per-request liveness gate, and the reason a host never needs an
// admin-privileged user lookup to refresh a display name onto a request.
//
// The verdict is the SAME gate that guards token mint at login and refresh
// (ensureUserAccess): deleted, reserved and banned accounts are denied, and an
// expired temporary ban is cleared and allowed. Both paths evaluate
// livenessAllowed, so they cannot drift.
//
// Errors PROPAGATE. Callers are authorization gates and must fail CLOSED on a
// lookup failure rather than read an outage as "allowed" — the same contract
// RoleSlugsByUsers carries. IDs that match no row are absent from the map,
// which a gate must also treat as a denial.
func (s *Service) UserLivenessByIDs(ctx context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
	out := map[string]authkit.UserLiveness{}
	if s.pg == nil || len(ids) == 0 {
		return out, nil
	}
	q := db.New(db.ForSchema(s.pg, s.dbSchema()))
	rows, err := q.IdentityUserLivenessByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		u := &User{
			ID:            r.ID,
			Email:         r.Email,
			Username:      r.Username,
			EmailVerified: r.EmailVerified,
			BannedAt:      r.BannedAt,
			BannedUntil:   r.BannedUntil,
			BanReason:     r.BanReason,
			BannedBy:      r.BannedBy,
			DeletedAt:     r.DeletedAt,
			AvatarURL:     r.AvatarUrl,
		}
		// Same lazy unban the single-user gate performs, so a temporary ban that
		// has run out is cleared here too rather than only on the login path.
		if err := s.autoUnbanIfExpired(ctx, u); err != nil {
			return nil, err
		}
		l := authkit.UserLiveness{
			ID:            r.ID,
			Allowed:       livenessAllowed(u, r.Reserved),
			EmailVerified: r.EmailVerified,
		}
		if u.Username != nil {
			l.Username = *u.Username
		}
		if u.Email != nil {
			l.Email = *u.Email
		}
		if u.AvatarURL != nil {
			l.AvatarURL = *u.AvatarURL
		}
		out[r.ID] = l
	}
	return out, nil
}
