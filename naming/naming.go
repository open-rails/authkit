// Package naming is the naming policy AuthKit applies to usernames (tenant
// names, renamed only by an operator, keep the former-name reservation), for
// a host to apply to its own names (an OpenRails merchant's):
//
//   - An owner may rename itself, at most once per RenameCooldown.
//   - A name it renamed away from forwards to it, and nobody else may claim
//     it, for FormerNameReservation.
//   - A deleted owner's names stay reserved forever and resolve to no one.
//
// It depends only on the standard library.
package naming

import "time"

const (
	// RenameCooldown is the least time between two renames of one owner.
	RenameCooldown = 72 * time.Hour
	// FormerNameReservation is how long a name renamed away from forwards
	// to its owner and stays reserved for it.
	FormerNameReservation = 90 * 24 * time.Hour
)

// NextRename is the earliest instant an owner whose name last changed at
// changed may rename again.
func NextRename(changed time.Time) time.Time { return changed.Add(RenameCooldown) }

// FormerNameExpiry is when a name its owner renamed away from at renamed
// stops forwarding and may be claimed by another.
func FormerNameExpiry(renamed time.Time) time.Time { return renamed.Add(FormerNameReservation) }
