package embedded

// #263: schema-build validation of InstanceCreationDef.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func creationPersona(mutate func(*PersonaDef)) PersonaDef {
	p := PersonaDef{
		Name:   "org",
		Parent: RootPersona,
		Roles:  []RoleDef{{Name: "member", Permissions: []string{"org:catalog:read"}}},
		Creation: InstanceCreationDef{
			Enabled:       true,
			SlugPattern:   `[a-z0-9][a-z0-9-]{0,30}`,
			ReservedSlugs: []string{"platform"},
		},
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func TestInstanceCreationSchemaValidation(t *testing.T) {
	// Valid config builds; the pattern is anchored (partial matches rejected).
	sch, err := BuildSchema(creationPersona(nil))
	require.NoError(t, err)
	require.True(t, sch.CreationEnabled("org"))
	require.False(t, sch.CreationEnabled(RootPersona))
	require.True(t, sch.creationSlugAllowed("org", "acme"))
	require.False(t, sch.creationSlugAllowed("org", "with.dots"), "pattern must be anchored, not substring-matched")

	// A persona with no pattern admits anything the built-in rule admits.
	sch, err = BuildSchema(creationPersona(func(p *PersonaDef) { p.Creation.SlugPattern = "" }))
	require.NoError(t, err)
	require.True(t, sch.creationSlugAllowed("org", "with.dots"))

	// Nested (non-root-parented) personas cannot enable creation.
	_, err = BuildSchema(
		creationPersona(func(p *PersonaDef) { p.Creation = InstanceCreationDef{} }),
		PersonaDef{
			Name: "repo", Parent: "org",
			Roles:    []RoleDef{{Name: "member", Permissions: []string{"repo:contents:read"}}},
			Creation: InstanceCreationDef{Enabled: true},
		},
	)
	require.ErrorContains(t, err, "instance creation requires parent")

	// A malformed slug pattern fails the build.
	_, err = BuildSchema(creationPersona(func(p *PersonaDef) { p.Creation.SlugPattern = "[" }))
	require.ErrorContains(t, err, "creation slug pattern")

	// Reserved slugs must themselves be valid instance slugs.
	_, err = BuildSchema(creationPersona(func(p *PersonaDef) { p.Creation.ReservedSlugs = []string{"Not Valid"} }))
	require.ErrorContains(t, err, "reserved slug")

	// The escalation role must exist in the ROOT catalog.
	_, err = BuildSchema(creationPersona(func(p *PersonaDef) { p.Creation.ReservedEscalationRole = "ghost" }))
	require.ErrorContains(t, err, "not a root catalog role")

	// The root persona itself can never enable creation (NewGroupSchema
	// directly — BuildSchema's root merge does not carry Creation).
	_, err = NewGroupSchema(PersonaDef{Name: RootPersona, Creation: InstanceCreationDef{Enabled: true}})
	require.ErrorContains(t, err, "root singleton cannot enable instance creation")
}
