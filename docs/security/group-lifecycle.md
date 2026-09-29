# Permission-group deletion lifetimes

Deleting a group, soft or `PurgeGroup`, keeps its slug reserved;
`PurgeGroupOptions.ReleaseSlug` frees it. Earlier aliases keep the expiry their
renames promised.

Custom-role edits update current holders. Deleting a custom role retires its
assignments, API keys and deferred invites in the same transaction; recreating
the spelling starts with no prior grants. Definition changes and grant writers
must serialize on the same group and inspect the current definition under that
lock. Existing actor authorization requirements remain in force.

Custom-role lifecycle mutations lock the group before definition, assignment,
key or invite rows. Transactional registration consumes role-carrying account
invites in that same order.

Permission reads join assignments and custom definitions in one statement, and
API-key verification joins the key and its custom definition. A concurrent
role deletion/recreation cannot combine an old grant with replacement authority.
This does not change who may assign roles or the separate final-owner policy.

One database workflow covers release/reservation, earlier alias expiry,
deletion rollback and concurrent rename; role edits, reference retirement and
delete/recreate; five waiting grant writers; and membership, application and
key reads at the deletion boundary.
