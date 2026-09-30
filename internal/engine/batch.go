package engine

import (
	"slices"

	"github.com/open-rails/authkit/iam"
)

// inBatches calls read with ids iam.MaxBatch at a time: a batch read takes any
// number of ids, and no query binds more than that.
func inBatches[T any](ids []T, read func([]T) error) error {
	for batch := range slices.Chunk(ids, iam.MaxBatch) {
		if err := read(batch); err != nil {
			return err
		}
	}
	return nil
}
