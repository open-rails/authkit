package authbase

// OrgMembership is a user's membership in an org with its optional roles.
type OrgMembership struct {
	Org   string
	Roles []string
}
