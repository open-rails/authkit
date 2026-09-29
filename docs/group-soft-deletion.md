# Group deletion

Your app deletes the entity a group guards, so it checks its own permission
first and then calls `DeleteGroup(ctx, iam.OperatorActor(), iam.GroupByID(id))`,
with `authkit.InTx(tx)` to delete its own row in the same transaction. Any
other actor is refused. The group stops resolving and grants nothing: its
roles, API keys and applications confer no authority, it accepts no authority
mutations, and it imposes no last-owner obligation. Its rows stay, and deleting
it again changes nothing. Root cannot be deleted. There is no restore.

`Group`, `Groups` and `ListGroups` with `IncludeDeleted` still return a deleted
group, with `DeletedAt` set, for host cleanup. Group routes, membership lists
and authorization skip it.

`PurgeGroup(ctx, iam.OperatorActor(), iam.GroupByID(id))` permanently deletes a
live or deleted group with every role, custom role, key and link in it.
Retention is the host's policy; AuthKit schedules no purge.

Group deletion takes the same authority lock as account deletion, so an
application that owns groups elsewhere cannot leave them without a usable owner
when its controlling group goes.
