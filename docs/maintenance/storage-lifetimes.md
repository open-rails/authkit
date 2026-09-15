# AuthKit storage lifetimes

Group assignments are current state: at most one row per group and subject.
Replacing a role updates that row; revoking it deletes the row. The old soft
deletion column retained incomplete, unread history and is removed before v1.
The unused creation/update timestamps are removed from assignments too.
Security-event retention is separate; assignment rows are not an audit log.

API keys and invitations keep terminal metadata for 90 days after the first
expiry/revocation/redemption event. Cleanup removes at most 5,000 eligible rows
per table per maintenance call, using indexed terminal timestamps. A later
maintenance call resumes; live rows and permanent name reservations remain.
Session/event/alias retention keeps its existing documented behavior.

This is a pre-v1 schema hard cut. Fresh databases receive the final table shape;
there is no upgrade or data-preservation path for an earlier AuthKit schema.
Hosts own an explicit reset or fresh-schema switch. No cleanup affects another
application's database objects or migration ledger.
