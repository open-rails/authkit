# Authentication discovery

`GET {api}/capabilities` exposes `external_login_providers`, a sorted array of configured external login provider summaries. It includes both OIDC providers such as Google and OAuth2 providers such as Discord; each retains its existing ID, display name and login/registration/link flags. There is no legacy `providers` response field.

The `password` section publishes the operator policy set by `embedded.Config.Password` (`password.Policy{MinLength, MaxLength}`, default 8..128, counted in Unicode characters, maximum ceiling 1024): `{"login": true, "min_length": 8, "max_length": 128}`. Every password write (registration, reset, change, admin set, bootstrap plaintext) enforces it and fails with `password_too_short` or `password_too_long`, both with `param: "password"` and `metadata: {"min_length": N, "max_length": M}`.

`GET {api}/me/groups` is always available to an authenticated local user, including deployments that declare only the intrinsic root persona. It returns the caller's current actual assignments with `group_id`, `persona`, `instance_slug` and `role`. A user with no assignments receives `{"object":"list","data":[]}`. It neither implies root membership for every user nor allows selecting another user's identity in query parameters. Group management routes still follow their configured persona capabilities.
