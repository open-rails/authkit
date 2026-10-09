package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// ProvisioningTargets reports the delivery of each Config.Provisioning
// target: when it last delivered everything it sent, since when it has been
// failing and why, and how many users wait to be sent.
func (a *Client) ProvisioningTargets(ctx context.Context) ([]iam.ProvisioningTarget, error) {
	return a.ops.ProvisioningTargets(ctx)
}
