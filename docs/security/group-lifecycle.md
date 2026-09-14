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
