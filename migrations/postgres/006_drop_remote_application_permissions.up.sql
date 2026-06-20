-- Hard-cut of the remote_application DIRECT-grant permission plane (#95: unify
-- on roles). A remote_application's authority is now derived ENTIRELY from its
-- org role membership (profiles.remote_application_org_roles ->
-- profiles.org_role_permissions); there is no per-application direct permission
-- list. The profiles.remote_application_permissions table (its index) carried
-- that direct grant and is removed wholesale.

SET lock_timeout = '10s';

DROP TABLE IF EXISTS profiles.remote_application_permissions;
