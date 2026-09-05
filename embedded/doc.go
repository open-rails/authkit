// Package embedded is the AuthKit engine: the concrete *Client a host
// constructs with New and holds directly, and the authkit/authhttp transport
// mounts. Data types hosts exchange with it live in the root authkit package;
// configuration, dependencies, sender/provider interfaces and engine-only
// types live here.
package embedded
