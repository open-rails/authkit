# Invitation storage consolidation proposal

AuthKit currently stores two invitation workflows in separate tables:
`group_invite_links` invites an existing user into a group, while
`account_registration_invites` admits a new account and can attach a group role.
They have the same hashed-token, inviter, expiry, revocation and bounded-terminal
retention lifecycle. This proposal is design-only; the current v1 branch does not
change either table.

A future hard-cut baseline may replace both with one `invitations` table:

```sql
CREATE TABLE profiles.invitations (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  kind text NOT NULL CHECK (kind IN ('group_link', 'account_registration')),
  email public.citext,
  permission_group_id uuid REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role text,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  redeemed_at timestamptz,
  consumed_at timestamptz,
  consumed_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (kind = 'group_link' AND permission_group_id IS NOT NULL AND role IS NOT NULL
      AND email IS NULL AND consumed_at IS NULL AND consumed_by IS NULL)
    OR
    (kind = 'account_registration' AND email IS NOT NULL
      AND ((permission_group_id IS NULL) = (role IS NULL)))
  )
);
```

The exact final checks must preserve the existing semantics: group links are
single-use membership links and may not create an account; registration invites
are email-bound, atomically consumed with user creation and optional membership;
revocation and expiry reject redemption; and concurrent redemption has exactly one
winner. Public methods remain purpose-specific (`CreateGroupInviteLink`,
`CreateAccountRegistrationInvite`, `RedeemGroupInviteLink`, and registration
consumption) even though storage is shared. A token's `kind` is checked before
any group or account mutation, so a token cannot cross workflows.

Before deleting either source table, a real PostgreSQL test must cover concurrent
same-token redemption, wrong-kind refusal, already-member idempotence, expiry,
revocation, inviter deletion, group deletion, and cleanup after the 90-day
terminal window. The test must also prove that a failed user creation rolls back
`consumed_at` and that cleanup deletes at most the existing bounded batch. No
compatibility reader or dual-write path is planned; this proposal requires a fresh
pre-v1 schema and coordinated consumer cutover.
