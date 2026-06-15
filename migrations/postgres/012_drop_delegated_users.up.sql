-- #81 REVERSAL (owner 2026-06-15): re-drop profiles.delegated_users.
-- #81 restored it (011) as a "shared FK anchor" for openrails + tensorhub. That
-- premise was wrong: the INVOKER ("under whose authority an action happened") is a
-- POLYMORPHIC principal (native-user | delegated-user | service-token | issuer/JWKS)
-- stored as OPAQUE TEXT (a stable uuidv7) with NO foreign key — openrails can't FK
-- across authkit's four principal tables (separate schema) or across apps. So nothing
-- FKs to this table; #78's original "not load-bearing" finding stands. Usage visibility
-- and per-invoker limits live in openrails keyed by the opaque invoker text. See
-- openrails#491 (paired invoker_id-FK -> invoker-text reversal).
--
-- CASCADE so it succeeds regardless of cross-repo migration order: an existing DB may
-- still carry openrails#491/027's invoker_id FK referencing this table (openrails#491's
-- own migration drops that column independently). NEW numbered migration; idempotent.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

DROP TABLE IF EXISTS profiles.delegated_users CASCADE;
