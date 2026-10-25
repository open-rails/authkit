# Issuer proof for a server-bound linking challenge

The existing issuer client owns PKCE, random state, popup origin/source checks,
DPoP and ID-token response checks. Add a caller-supplied nonce option for a
server-issued challenge while preserving independently generated state/PKCE and
the random nonce default. Empty or invalid supplied values must fail before
navigation rather than disabling nonce verification.

Expose the current validated ID token with `getIDToken`, consistent with
`getAccessToken`, without retaining a previous identity's token across a new
exchange, logout or generation change. SaaS uses `persist:false` and never
stores its original merchant credential in the callback URL or browser storage.

One real issuer-browser case joins the existing critical harness and ordinary
CI roster. It covers the new nonce and getter plus wrong-nonce refusal and
identity/logout clearing. The current minimal UI suite contains no issuer-client
case; this adds that missing boundary without creating a second test harness.

This task is an additive browser-client prerequisite. Root coordinates it with
the separate callback-tenant change for one full AuthKit gate and public release.
