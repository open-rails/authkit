# Ownership and role changes

Each group has at most one direct role per subject. Runtime replacement requires the actor to cover both the displaced and requested grants. Repeating an assignment still requires authorization but does not remove ownership. Invitations cannot replace a stronger existing role.

An owner is a live, unbanned user or enabled remote application assigned the catalog `owner` role. Custom roles do not replace this recovery authority. Owner-removing operations must leave another usable owner; grant that owner first. New, never-owned groups may remain empty during bootstrap. Deleting a group intentionally ends its ownership obligation. Cleanup of an already unusable principal does not create a new ownership loss.

Authority and account lifecycle mutations serialize with one transaction advisory lock per AuthKit schema, before group, account, MFA, or session row locks. This deliberately trades parallel administrative write throughput for a small consistent boundary across ancestor grants, custom roles, and account liveness. Ordinary authentication, reads and session issuance do not acquire it.
