# Runtime and operation Client

AuthKit's local owner is `embedded.Runtime`. Construct it with `embedded.New`, obtain its engine-free operation interface with `runtime.Client()`, compose `runtime.RiverJobs()` with the host fleet, and close the runtime when the host stops. The operation view carries no pool, key, configuration, bootstrap or lifecycle methods. It creates no additional engine.

Configure HTTP once after local provisioning with `runtime.ConfigureHTTP(authhttp.Config{...})`. The HTTP configuration builds AuthKit's existing canonical service and mount through a small local construction interface, avoiding an `embedded`/`authhttp` import cycle. The runtime owns HTTP cleanup. Framework adapters obtain `Routes(runtime)` and register that configured inventory once. Root-anchored discovery, documents and OIDC paths retain their protocol contracts.

The root `authkit.Client` is an operation contract, not an HTTP server backend. This change does not implement a remote client or expose in-process administrator authority on the network. Future remote implementations must authenticate each privileged operation and preserve typed inputs, results and errors.

Tracked by AuthKit #377 in the shared tracker.

This pre-v1 change removes the concrete `embedded.Client` name; use
`embedded.Runtime`. Root `authkit.Client` no longer includes local provisioning,
maintenance or sender-availability methods. Keep `EnsureRootGroup`, bootstrap
reconciliation, sender probes and cleanup on the runtime. No compatibility alias
or second operation implementation is introduced.
