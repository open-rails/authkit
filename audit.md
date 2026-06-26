# AuthKit audit

The recent restructure yesterday already fixed real stuff, so this is kinda cut short: senders moved to `adapters/`,
`testing/` renamed to `authtest/`, proper `cmd/` folders, dead `roles/` and
`identity/` packages deleted. I think this is good progress.


1. The `Client` interface has 93 methods

`client.go` has one interface called `Client`, and it has 93 methods on it.
Everything is on it: admin stuff, users, tokens, groups, sessions, passwords,
providers, bootstrap. All in one type.
I think the first thing I learned about Golang was that INterfaces should be thin so I know this is bad.
- If we want to use AuthKit, or write a fake for a test, we have to deal with
  all 93 methods even if you only care about 3.
Nobody can hold 93 methods in their head, so it's hard to know what's actually in there. 
We also auto-generate remote and server code from this interface, so all 93 become network calls someone has to maintain.

There are two smaller interfaces carved out of it for people who only need a few methods I guess? That's a workaround for the real problem.

Fix: split it into a few small interfaces by topic (users, tokens, groups, etc).

Progress:
- Stage 1 (done): taught the code generator to handle a `Client` built from
  smaller embedded interfaces. It used to only read one flat interface. No output
  change yet (still the same 93 methods), this just unblocks the actual split.
- Stage 2 (done): split the 93 methods into 15 small interfaces named by topic
  (Users, Passwords, Tokens, Groups, Sessions, APIKeys, Providers, RemoteApps,
  Passwordless, Bootstrap, Senders, Entitlements, Maintenance, Admin, Roles) and
  `Client` now just embeds them. Same 93 methods, generated code byte-identical,
  all tests pass. Hosts can now depend on the one small interface they use.
  Reviewed before committing: dropped a junk-drawer interface, fixed a couple of
  miscategorized methods, and removed a duplicate slice.


2. Service file is 4,792 lines

`internal/authcore/service.go` is the engine, and it's 4,792 lines in a single
file. It makes reviews and merge conflicts worse.

Fix: split it into smaller files by topic, same as the interface above.


3. Login providers use a tiny made-up language

To add an external login provider, you write config that includes a list of
string commands like `Transforms: ["string", "trim"]`. It's a small custom
language for "take this field and clean it up."

For Google, Apple, Discord and the like (OIDC), we don't need any of this. Those login fields are standardized, so a normal OIDC library just reads them.
For the rare odd provider, a plain Go function would be clearer and could do more than a fixed list of string commands.

This is probably a big reason the provider setup is confusing to read.

Fix: read standard OIDC fields directly, and for odd providers let the app pass a small Go function instead of the string list.


4. Three folders don't match their package name

`http/` is package `authhttp`, `oidc/` is package `oidckit`, `jwt/` is package
`jwtkit`. In Go the folder name and the package name are normally the same. Here
you see one name in the path and a different one in the code, so you have to
remember both. Small thing, easy to fix, just annoying.


5. Leftover mess from the restructure

There's an empty `core/` folder still sitting there after the code moved to
`embedded/`, and a dead comment in `contract.go`. Just delete them. Minor, but it
makes you unsure what's actually still in use.


------- What's already good

- It uses trusted libraries for the hard crypto parts instead of writing its own.
- The token-checking path is kept light, so a service that only verifies tokens
  doesn't drag in the database. That's a smart split.
- Moving the shared types to the root package was the right call.


