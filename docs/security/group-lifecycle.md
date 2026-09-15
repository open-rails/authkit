# Permission-group deletion lifetimes

Deleting a permission-group intentionally deletes its descendant subtree.
Default deletion permanently reserves every deleted group's canonical name;
explicit release applies to the whole deleted subtree. Earlier aliases retain
the exact expiration promises made by their original renames.

Custom-role edits update current holders. Deleting a custom role retires its
assignments, API keys and deferred invites in the same transaction; recreating
the spelling starts with no prior grants. Definition changes and grant writers
must serialize on the same group and inspect the current definition under that
lock. Existing actor authorization requirements remain in force.

Custom-role lifecycle mutations lock the group before definition, assignment,
key or invite rows. Transactional registration consumes role-carrying account
invites in that same order. Direct `PermissionGroupStore` use is a trusted host
operation: callers of DeleteGroup/DeleteCustomRole must supply a transaction;
DeleteCustomRole also requires the group lifecycle lock.

Permission reads join assignments and custom definitions in one statement, and
API-key verification joins the key and its custom definition. A concurrent
role deletion/recreation cannot combine an old grant with replacement authority.
This does not change who may assign roles or the separate final-owner policy.

The single database workflow covers subtree release/reservation, earlier alias
expiry, deletion rollback, late child creation and concurrent rename; role edits,
reference retirement/replay and delete/recreate; five waiting grant writers; and
controlled membership/application/key reads at the deletion boundary. It replaces
the obsolete standalone cascade fixture while retaining its subtree/role cleanup
assertions. Account-invite consumption ordering is supplied by the shared
registration transaction implementation.
