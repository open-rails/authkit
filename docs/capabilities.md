# Authentication discovery

`GET {api}/capabilities` exposes `external_login_providers`, a sorted array of configured external login provider summaries. It includes both OIDC providers such as Google and OAuth2 providers such as Discord; each retains its existing ID, display name and login/registration/link flags. There is no legacy `providers` response field. Password, passkey, Solana and other capability sections are unchanged.

`GET {api}/me/groups` is always available to an authenticated local user, including deployments that declare only the intrinsic root persona. It returns the caller's current actual assignments with `group_id`, `persona`, `instance_slug` and `role`. A user with no assignments receives `{"object":"list","data":[]}`. It neither implies root membership for every user nor allows selecting another user's identity in query parameters. Group management routes still follow their configured persona capabilities.
