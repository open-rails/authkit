// Package iam holds AuthKit's shared identity and access vocabulary: users,
// subjects, groups, roles and permissions, principals, remote applications,
// credential parsing, naming policy, and the one error catalog with its wire
// envelope. It depends only on the standard library, so the engine, the
// DB-less verify package and hosts can all share it.
package iam
