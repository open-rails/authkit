package authkit

// PersonaCapabilities are opt-in generated management capabilities for a persona.
type PersonaCapabilities struct {
	APIKeys            bool
	RemoteApplications bool
	CustomRoles        bool
}

// InstanceCreationDef opts a persona into the generated creation route (#263):
// POST /<persona> creates an instance with the authenticated user seeded as its
// owner. Only root-parented personas may enable it. AuthKit owns the anti-squat
// velocity limits (per-IP + per-user); host COST gates plug in through
// WithInstanceAdmission. Zero value = no creation route (existing behavior).
type InstanceCreationDef struct {
	// Enabled mounts POST /<persona>. Off by default.
	Enabled bool
	// SlugPattern further restricts creatable slugs beyond the built-in
	// instance-slug rule: an unanchored regexp source, anchored (^...$) at
	// schema build. Empty = built-in rule only.
	SlugPattern string
	// ReservedSlugs are exact lowercase slugs creatable only by callers holding
	// ReservedEscalationRole in the root group (a list is config, a route is not).
	ReservedSlugs []string
	// ReservedEscalationRole is the root-group role that may create reserved
	// slugs. Empty = reserved slugs are not creatable through this route at all.
	ReservedEscalationRole string
}
