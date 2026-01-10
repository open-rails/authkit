package roles

import "github.com/google/uuid"

// NamespaceRoleIDs is the UUID namespace used to derive stable role IDs from slugs.
//
// Role IDs are computed as UUIDv5(namespace, "role:"+slug). Slugs are treated as immutable identity.
//
// This is part of the auth mechanism (stable identity), not app-specific role taxonomy.
var NamespaceRoleIDs = uuid.MustParse("ef5d0f45-83c6-5dbe-b15a-e017bc88ab5a")

func IDFromSlug(slug string) uuid.UUID {
	return uuid.NewSHA1(NamespaceRoleIDs, []byte("role:"+slug))
}

