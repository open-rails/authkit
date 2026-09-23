# Retained permission-group deletion

Owner: `/root/astra_neutral_resume`.
Purpose: generic inactive groups for application-owned retained cleanup (#1052).
Worktree: `/home/fidika/cozy/.worktrees/authkit/1052-group-retirement-20260923`.
Branch: `feat/1052-group-retirement-20260923`.
Base: `c99acde0d3391c23f4df29984adac38e8b012d18` (published v0.126.0).

The trusted host's `Client.SoftDeleteGroupInstanceByID` retires a nonroot group's
entire subtree by immutable ID, returns its descriptor with `DeletedAt`, and
preserves the first timestamp on retry. It retains identity/name reservations,
roles, keys, applications and history. The root group cannot retire. No restore
API or implicit cleanup schedule is introduced.

Retired groups confer no live native or machine authority, cannot accept new
authority mutations or children, and impose no last-owner account obligation.
Active groups retain the existing final-owner invariant. Retirement and account
deletion use the same authority transaction lock; external active groups cannot
be orphaned when their application owner belongs to the retiring subtree.

The existing hard DeleteGroupInstanceByID remains the explicit trusted purge
operation. Retention duration and due-time validation belong to the application;
AuthKit does not read application tables or enforce an application-specific clock.
