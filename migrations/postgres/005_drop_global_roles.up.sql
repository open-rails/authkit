-- Hard-cut of the legacy "global roles" plane. The platform authority plane is
-- now Layer-2 platform RBAC (003_platform_rbac.up.sql): profiles.platform_roles
-- + profiles.platform_user_roles granting `platform:*` permissions, assigned to
-- users directly. The old profiles.global_roles / profiles.global_user_roles
-- tables (and their triggers/functions) carried that authority as a token claim
-- and are removed wholesale.

SET lock_timeout = '10s';

DROP TRIGGER IF EXISTS global_roles_set_id_from_slug ON profiles.global_roles;
DROP TRIGGER IF EXISTS global_roles_slug_immutable ON profiles.global_roles;

DROP TABLE IF EXISTS profiles.global_user_roles;
DROP TABLE IF EXISTS profiles.global_roles;

DROP FUNCTION IF EXISTS profiles.trg_global_roles_set_id_from_slug();
DROP FUNCTION IF EXISTS profiles.trg_global_roles_slug_immutable();
