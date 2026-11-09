# Importing sign-in history

`Client.ImportSessionEvents` is an embedded host operation beside `ImportUsers`.
The host supplies system authority; it takes no caller identity and has no HTTP
route. Select the account directory with `ForTenant` as for other account imports.

```go
result, err := client.ImportSessionEvents(ctx, []iam.ImportSessionEvent{{
    UserID: accountID,
    ID: "legacy-logins:12345",
    Kind: iam.SessionEventCreated,
    OccurredAt: time.Unix(legacyCreatedAt, 0),
    Issuer: "doujins.com",
    Method: "legacy-logins",
    IP: net.IP(legacyPackedIP).String(),
    UserAgent: legacyAgent,
}})
```

Use `SessionEventCreated` for a successful sign-in and `SessionEventFailed` for
a failed attempt. Other kinds are refused. `OccurredAt` must be nonzero and no
later than the import starts. `Issuer` defaults to `Config.Token.Issuer`; the host
may instead name the legacy site. `Method` or `Reason` must name the source.
`IP` takes a literal IPv4 or IPv6 address; decode binary `inet_pton` data in the
host. An empty IP or user agent means unknown. Text must be valid UTF-8 without
NUL. Limits in bytes: ID 256, issuer 2048, method and reason 256 each, user agent
4096. Whitespace alone cannot name an ID, issuer or source.

Each call accepts up to 1,000 entries, matching the transaction chunk size of
`ImportUsers`. A larger call fails with `invalid_request` before any writes;
an empty call succeeds. Options, including `InTx`, are unsupported.

`result.Rows` reports each processed input index in order:

| Status | Reason | Meaning |
| --- | --- | --- |
| `imported` | empty | History entry committed. |
| `duplicate` | empty | This account already has the stable ID; nothing changed. |
| `refused` | `unknown_account` | No account in the selected tenant, including a foreign account. |
| `refused` | `deleted_account` | The account is deleted. |
| `refused` | `too_old` | Entry predates `SessionEventRetention` (365 days by default). |
| `refused` | `invalid` | An input field failed the rules above, or the account ID is invalid. |

Validation runs before retention, then account lookup. Invalid or expired
entries therefore report that reason even when the account is absent. Negative
retention keeps history forever. The retention cutoff is fixed at call start;
entries exactly at it are eligible. Replaying an entry after it ages out reports
`too_old` and does not restore it. Regular cleanup prunes imported and native
entries together.

Stable IDs are scoped to an account, independent of issuer and kind. Namespace
them by source if importing more than one source. A duplicate never updates
the original entry, even when submitted fields differ. Deduplication is enforced
in PostgreSQL, including concurrent calls and retries after a lost response.
Each entry commits independently. On database failure or cancellation, the call
returns an error and completed results; retrying the batch is safe.

Imported entries list through `ListSessionEvents` and the existing admin history
view, with no session ID. They create no sessions, notifications or account
events, and do not change account state. Set legacy `LastLogin` separately through
`ImportUsers` with `ImportMerge`; use the latest successful source sign-in.
Migration 0027 adds a nullable import key and a partial unique index, with no
backfill of native history.
