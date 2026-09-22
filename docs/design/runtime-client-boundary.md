# Runtime and operation Client

`embedded.New(config, deps)` constructs a local `embedded.Runtime` around a named private engine. The runtime exposes only Client, lifecycle, route/verifier assembly, River contributions and the entitlement-provider dependency needed to resolve billing construction order. There is no public engine, database, configuration, signer or Genesis accessor, and no business methods are promoted onto Runtime.

Set `config.HTTP = authhttp.Config{...}` before construction. The runtime owns HTTP setup and closes HTTP before its own engine resources. Framework adapters obtain `Routes(runtime)` and mount once on the host root router; protocol-anchored discovery, document and OIDC paths remain anchored. A later one-shot ConfigureHTTP remains available when real provisioning dependencies require it.

After the host applies migrations, database-backed construction atomically installs explicitly declared group containment and the root singleton under the authority lock. Omitted or empty RBAC leaves existing shared topology intact. Construction never assigns user roles or restores revoked authority. Explicit operator commands use Client.AdminAssignGroupRole and Client.AdminUnassignGroupRole; actor-bearing requests use the existing checked As operations. Both preserve subject MFA and final-owner invariants.

`runtime.Client()` returns the stable typed application operation interface through a narrow in-process view. It borrows the engine and owns no resources. The Client contract uses root DTOs, contexts and ordinary values, so a future remote transport can implement the same operations without a local runtime. No remote protocol or HTTP exposure of trusted administrator authority is added here.

The HTTP transport receives a local backend capability only during construction, avoiding an embedded/authhttp import cycle. That transport capability is not a portable Client and Runtime exposes no accessor for it. Document providers continue to accept explicit signer/store construction dependencies independently of Runtime.

Tracked by AuthKit #377 in the shared tracker. This pre-v1 cut removes the previously exported engine methods and Genesis surface; it does not retain aliases or forwarding business methods on Runtime.
