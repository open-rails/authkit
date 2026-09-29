# Events

`Deps.OnEvent` receives committed account and group changes as `iam.Event`,
durably, through River.

```go
deps.OnEvent = func(ctx context.Context, e iam.Event) error {
	switch e.Kind {
	case iam.EventUserBanned:
		return bans.Record(ctx, e.ID, e.UserID, e.ActorKind, e.ActorID, e.Reason, e.Until)
	case iam.EventRoleGranted, iam.EventRoleChanged, iam.EventRoleRevoked:
		return members.Apply(ctx, e.ID, e.GroupID, e.UserID, e.Current)
	}
	return nil // ignore kinds you do not handle
}
```

## Guarantees

- **Transactional.** A change records its events in its own transaction, so a
  refused or rolled-back change records nothing, whichever surface made it
  (HTTP, `Auth` methods, sign-in flows, River jobs).
- **At least once.** Delivery runs after commit, outside any transaction, and
  may repeat. `Event.ID` is the same on every delivery: deduplicate on it.
- **Ordered per subject.** Events about one user (group events: one group)
  arrive in commit order. Different subjects interleave.
- **Retried.** A hook error or panic is retried 2s, 4s, … up to an hour apart,
  forever, and holds back that subject's later events. Return `nil` for kinds
  you ignore.
- **No secrets.** Events carry ids, the changed values and the actor, never a
  password, hash, token or code.

## Kinds

| Kind | Fields |
|---|---|
| `user.registered` | `UserID`. Every account creation except `ImportUsers`. |
| `user.email_changed`, `user.phone_changed`, `user.username_changed` | `UserID`, `Previous` → `Current` (`""` when none) |
| `user.banned` | `UserID`, `Reason`, `Until` (nil: indefinite) |
| `user.unbanned` | `UserID`; a ban in force was lifted (expiry records nothing) |
| `user.deleted`, `user.restored`, `user.purged` | `UserID`; purged follows the removal of the account row |
| `role.granted`, `role.changed`, `role.revoked` | `GroupID`, `Persona` (`root` for root roles), `UserID` or `ApplicationID`, role `Previous` → `Current` |
| `group.created`, `group.deleted`, `group.purged` | `GroupID`, `Persona` |

`ActorKind`/`ActorID` name who made the change (`ActorID` is empty for the
operator); both are empty when AuthKit acted on its own, such as the end of a
recovery window. Removing an account, application or group records no role
events for the assignments that go with it.

## Delivery

Each change writes one `account_events` row per subscribed deployment and a
River job in that deployment's fleet, reusing the account-lifecycle machinery
of `OnSoftDelete`/`OnHardDelete`/`OnRestore`. A deployment subscribes when it
starts with `OnEvent` set (it binds its River fleet in `New` or `RiverJobs`);
events before that are not recorded for it. With `Token.AccountIssuers`,
every subscribed deployment sharing the account store receives every event.
A delivered row is deleted. Pending rows block rebinding a deployment's River
schema, like pending deletion callbacks.
