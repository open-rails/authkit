package authkit

// PersonaCapabilities are opt-in generated management capabilities for a persona.
type PersonaCapabilities struct {
	APIKeys            bool
	RemoteApplications bool
	CustomRoles        bool
}
