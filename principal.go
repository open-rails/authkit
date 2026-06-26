package authkit

// PrincipalKind is the broad AuthKit credential class for a verified request.
type PrincipalKind string

const (
	PrincipalKindUser              PrincipalKind = "user"
	PrincipalKindAPIKey            PrincipalKind = "api_key"
	PrincipalKindRemoteApplication PrincipalKind = "remote_application"
	PrincipalKindDelegated         PrincipalKind = "delegated"
	PrincipalKindService           PrincipalKind = "service"
)

// Principal is the small generic-auth shape host adapters expose.
type Principal struct {
	Kind    PrincipalKind `json:"kind"`
	Issuer  string        `json:"issuer,omitempty"`
	Subject string        `json:"subject,omitempty"`
}
