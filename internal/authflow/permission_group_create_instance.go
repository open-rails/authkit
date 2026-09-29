package authflow

// CreateInstanceResult reports a generated-creation outcome. Created is false
// when the slug already existed and the caller is a member (idempotent return).
type CreateInstanceResult struct {
	// GroupID is the new (or idempotently returned) instance's uuid (#269). It
	// is populated on BOTH outcomes: the idempotent re-run is the bootstrap
	// path, so an id only on Created=true would leave the re-runner with
	// nothing. Empty only on error.
	GroupID      string
	InstanceSlug string
	Created      bool
}
