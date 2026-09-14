# Remote-attribute registry removal

The old remote-attribute registry has no required consumer in the fetched source
heads below. AuthKit already stopped hydrating attributes and exposing registry
HTTP routes. The engine methods, public DTO/reference helpers, error codes, SQL queries
and schema objects are removed. Opaque inline attributes and signed documents keep
their current contracts.

| Consumer | Fetched master |
|---|---|
| Doujins | `0ea039e501ad3dc73c0d1af9175ef38b3694aa26` |
| Hentai0 | `ffad07def9450df11684ba43e00c33a00bcd1051` |
| OpenRails | `e7ecbe6e40dd6aa984c0b65a76c76e41d6a54f48` |
| Cozy-art | `f31bb0c5ac25de922a5b6fde9dc36eddacae6b9c` |
| Tensorhub-v2 | `0f86b1b695e5b1204162c6a23f936b031047226f` |
| OpenRails SaaS | `3511ce85cba6f35c8ed6240a46ae6ee8b62e132a` |
| SocialKit | `f1115893757f9f6154da974158679dcecdfa226a` |

The census searched exported registry methods/types/errors, reference helpers,
and the table name across all tracked text at these Git heads. It found
no references. Consumer checkouts were neither edited nor fast-forwarded.

The owner explicitly declared all AuthKit-owned tables and data disposable
before v1. The registry table/index and unused `user_renames` table/write are
therefore removed from the pre-v1 schema. No compatibility table or forward-drop
migration is retained. Current parent links are restamped until the repository
consolidates its fresh baseline; existing pre-launch databases must be rebuilt
from that baseline. This does not authorize modifying another application's data.

The same fetched-head census found no `user_renames` reader or writer in a
consumer. Hentai0's only mentions are historical comments in
`tests/integration/username_rename_test.go` and `agents/test-audit.md`; its actual
rename workflow uses HTTP. Active aliases remain in `name_claims` and cooldowns
remain in `users.last_renamed_at`.

The generated query package omits unused table structs. Full root and adapter
compilation verifies those deleted internal models have no Go consumers.
The obsolete standalone profile-link fixture is replaced by provider-list
assertions in the existing HTTP profile/rename workflow. Existing naming,
inline-attribute and signed-document workflows continue to qualify the retained
behavior; the existing migrator workflow checks both default and custom schemas
contain neither removed table.
