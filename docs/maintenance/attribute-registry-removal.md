# Remote-attribute registry removal

The old remote-attribute registry has no required consumer in the fetched source
heads below. AuthKit already stopped hydrating attributes and exposing registry
HTTP routes. Remove its unused engine methods, public DTO/reference helpers,
error codes, and SQL queries. Opaque inline attributes and signed documents keep
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
and the table name in Go, TypeScript and Markdown at these Git heads. It found
no references. Consumer checkouts were neither edited nor fast-forwarded.

The historical `remote_application_attribute_defs` table and its rows remain.
No deployed database census was performed. Before a forward migration drops it,
record row counts for each consumer schema/database, decide whether any rows
need export, and check consumers outside this source inventory. Dropping the
retained table/index remains an unresolved part of tracker #362; released
migrations must remain byte-for-byte unchanged. This source cleanup does not
complete that schema acceptance criterion.
