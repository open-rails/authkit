package iam

// PrincipalKind is the broad AuthKit credential class for a verified request.
type PrincipalKind string

const (
	PrincipalKindUser              PrincipalKind = "user"
	PrincipalKindAPIKey            PrincipalKind = "api_key"
	PrincipalKindRemoteApplication PrincipalKind = "remote_application"
	PrincipalKindDelegated         PrincipalKind = "delegated"
)
