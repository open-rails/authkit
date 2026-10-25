CREATE TABLE account_inbox_scopes (
    scope text PRIMARY KEY,
    tenant_id uuid NOT NULL UNIQUE,
    account_schema text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
