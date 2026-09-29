// Package iam holds AuthKit's shared identity and access vocabulary: users,
// subjects, groups, roles and permissions, actors, remote applications,
// credential parsing, naming policy, and the one error catalog with its wire
// envelope. It depends only on the standard library, so the engine, the
// DB-less verify package and hosts can all share it.
//
// A persona is a type of permission group (channel, org, merchant). A
// permission group is one instance of a persona (/c/golang). root is the
// persona with exactly one group, the whole site. A permission is
// `<persona>:<resource>:<action>`; `*` may replace the action or everything
// after the persona, and the resource `self` is the group itself.
package iam
