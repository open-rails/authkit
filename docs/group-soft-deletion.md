# Group deletion

`DeleteGroup(ctx, actor, ref)` (and `DELETE {api}/{persona}/{slug}`) soft-deletes
a group; it needs `<persona>:self:delete`. The group stops resolving by slug and
grants nothing: its roles, API keys and applications confer no authority, it
accepts no authority mutations, and it imposes no last-owner obligation. Its
rows, slug and name reservations stay, and a retry keeps the first `DeletedAt`.
Root cannot be deleted. There is no restore.

`Group` by id, `Groups` and `ListGroups` with `IncludeDeleted` still return a
deleted group, with `DeletedAt` set, for host cleanup. Slug lookups, membership
lists and authorization skip it.

`PurgeGroup(ctx, iam.OperatorActor(), iam.GroupByID(id), opts)` permanently
deletes a live or deleted group with every role, custom role, key and link in
it. The slug stays reserved forever unless `opts.ReleaseSlug` is set. Retention
is the host's policy; AuthKit schedules no purge.

Group deletion takes the same authority lock as account deletion, so an
application that owns groups elsewhere cannot leave them without a usable owner
when its controlling group goes.
