package ops

import (
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
)

// Option adjusts one operation. Each operation names the kinds it takes and
// refuses any other: an option is never silently ignored.
type Option struct {
	kind  Kind
	apply func(*Options)
}

// Kind names an option.
type Kind string

const (
	KindTx             Kind = "InTx"
	KindIfRole         Kind = "IfRole"
	KindIncludeDeleted Kind = "IncludeDeleted"
)

// Options are one call's resolved options.
type Options struct {
	// Tx is the host's transaction the operation joins.
	Tx pgx.Tx
	// IfRole makes a removal apply only while the subject holds this role.
	IfRole iam.Role
	// IncludeDeleted makes a read return soft-deleted accounts too.
	IncludeDeleted bool
}

func InTx(tx pgx.Tx) Option {
	return Option{KindTx, func(o *Options) { o.Tx = tx }}
}

func IfRole(r iam.Role) Option {
	return Option{KindIfRole, func(o *Options) { o.IfRole = r }}
}

func IncludeDeleted() Option {
	return Option{KindIncludeDeleted, func(o *Options) { o.IncludeDeleted = true }}
}

// Resolve applies opts for op, refusing an option op does not take.
func Resolve(op string, opts []Option, takes ...Kind) (Options, error) {
	var out Options
	for _, opt := range opts {
		if opt.apply == nil {
			continue
		}
		ok := false
		for _, k := range takes {
			ok = ok || k == opt.kind
		}
		if !ok {
			return Options{}, fmt.Errorf("authkit: %s does not take %s", op, opt.kind)
		}
		opt.apply(&out)
	}
	return out, nil
}
