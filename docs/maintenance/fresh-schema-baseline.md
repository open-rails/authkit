# AuthKit v1 fresh schema baseline

AuthKit's pre-launch schema is being consolidated into one authored baseline.
Earlier AuthKit migration histories are unsupported and must be rebuilt from
approved source data. Migration never drops an existing application's tables.
The raw `migrations/postgres.FS` and `FSForSchema` interfaces remain available to
host-owned runners, using the canonical `authkit` ledger namespace.

`authkitmigrate.Migrate(ctx)` will return only an error. The removed `Applied`
receipt was inferred outside the migration lock and could attribute another
replica's work to the current call. There is no operational need for that
attribution in the current consumer census:

| Consumer/head | Current AuthKit migration consumption |
|---|---|
| Doujins `0ea039e5` | CLI prints Applied count; coordinator discards result |
| Hentai0 `ffad07de` | Raw FS migration runner |
| OpenRails `e7ecbe6e` | Discards Migrate result |
| Cozy-art `0ff4136b` | Raw FS migration runner and metadata tooling |
| Tensorhub `0f86b1b6` | Startup logs Applied names; tests assert old numbers |
| OpenRails SaaS `3511ce85` | Raw FS migration runner |

Consumers should report successful readiness after Migrate returns nil and test
required schema behavior instead of migration counts. Their dependency updates
must include the new return signature; no compatibility adapter is provided.

The baseline is checked against a PostgreSQL schema catalog and schema-only dump
from the complete prior chain, then exercised through default/custom schema,
repeat/concurrent migration, account, naming, credential and permission workflows.
