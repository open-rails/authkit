# Native callback target tenant

SaaS composes one shared AuthKit runtime with multiple account realms. Account-deletion and consent-revocation callbacks must retain the operation's resolved target directory instead of guessing ownership from a user ID.

AuthKit exposes a read-only `authkit.TenantFromContext(ctx)` accessor for the target already resolved by AuthKit's native tenant view or HTTP dispatch. It grants no authority and exposes no context setter. A missing target returns false. A callback must not treat the target as the caller's authenticated source identity.

Qualification extends the existing account lifecycle journey with real HTTP self-deletion and consent revocation in default and non-default tenant views of one runtime, plus a rejected foreign-token control. No callback policy or authorization semantics are changed. The focused existing lifecycle scenario passed under the race detector; full combined qualification and publication remain with the release coordinator.
