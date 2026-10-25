package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/notify"
)

// Apply atomically applies up to notify.MaxMutations exact identities.
func (s *Store) Apply(ctx context.Context, mutations []notify.Mutation) error {
	if len(mutations) == 0 {
		return nil
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.apply(ctx, tx, mutations)
	})
}

// ApplyTx joins the caller's transaction. Its savepoint makes the whole batch
// atomic even if the caller handles an error and commits other work in tx.
func (s *Store) ApplyTx(ctx context.Context, tx pgx.Tx, mutations []notify.Mutation) error {
	if len(mutations) == 0 {
		return nil
	}
	if tx == nil {
		return fmt.Errorf("%w: transaction required", notify.ErrInvalid)
	}
	return pgx.BeginFunc(ctx, tx, func(batch pgx.Tx) error {
		return s.apply(ctx, batch, mutations)
	})
}

func (s *Store) apply(ctx context.Context, tx pgx.Tx, mutations []notify.Mutation) error {
	if len(mutations) > notify.MaxMutations {
		return fmt.Errorf("%w: at most %d mutations", notify.ErrInvalid, notify.MaxMutations)
	}
	batch := make([]notify.Mutation, len(mutations))
	recipients := make([]notify.Recipient, len(mutations))
	for i, in := range mutations {
		var err error
		batch[i], err = notify.ValidateMutation(in)
		if err != nil {
			return err
		}
		if !s.visible(notify.Item{Input: batch[i].Input}) {
			return fmt.Errorf("%w: mutation outside app view", notify.ErrInvalid)
		}
		recipients[i] = in.Recipient
	}
	// Every batch locks recipients in the same order, independently of the
	// producer's input order. These locks also fence concurrent account erasure.
	audiences, ids, _, err := recipientSet(recipients)
	if err != nil {
		return err
	}
	for i, id := range ids {
		erased, err := s.lock(ctx, tx, notify.Recipient{Audience: notify.Audience(audiences[i]), ID: id})
		if err != nil {
			return err
		}
		if erased {
			return notify.ErrRecipientErased
		}
	}
	for _, in := range batch {
		if erased, err := s.appErased(ctx, tx, in.Input); err != nil {
			return err
		} else if erased {
			return notify.ErrRecipientErased
		}
		if err := s.applyOne(ctx, tx, in); err != nil {
			return err
		}
	}
	return nil
}

func mutationHash(in notify.Mutation) ([]byte, error) {
	if len(in.Data) > 0 {
		// Canonicalize object-key order without converting exact JSON numbers
		// to float64. A retry can have different insignificant JSON whitespace.
		decoder := json.NewDecoder(bytes.NewReader(in.Data))
		decoder.UseNumber()
		var data any
		if err := decoder.Decode(&data); err != nil {
			return nil, err
		}
		var err error
		in.Data, err = json.Marshal(data)
		if err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(b)
	return digest[:], nil
}

func (s *Store) applyOne(ctx context.Context, tx pgx.Tx, in notify.Mutation) error {
	digest, err := mutationHash(in)
	if err != nil {
		return err
	}
	key := []any{s.scope, in.Recipient.Audience, in.Recipient.ID, in.Origin.System, in.Origin.Scope, in.Origin.ID}
	const identity = `scope=$1 AND audience=$2 AND recipient=$3 AND source=$4 AND source_scope=$5 AND source_id=$6`
	var revision int64
	var previousHash []byte
	var visibility notify.Visibility
	var appID string
	err = tx.QueryRow(ctx, `SELECT producer_revision,producer_hash,visibility,app_id FROM `+s.table+` WHERE `+identity+` FOR UPDATE`, key...).Scan(&revision, &previousHash, &visibility, &appID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		if visibility != in.Visibility || appID != in.AppID {
			return fmt.Errorf("%w: origin visibility differs", notify.ErrConflict)
		}
		if revision > in.Revision {
			return nil
		}
		if revision == in.Revision {
			if bytes.Equal(previousHash, digest) {
				return nil
			}
			return fmt.Errorf("%w: producer revision has different content", notify.ErrConflict)
		}
		if in.Withdrawn {
			_, err = tx.Exec(ctx, `UPDATE `+s.table+` SET producer_revision=$7,producer_hash=$8,withdrawn=true,updated_at=clock_timestamp(),revision=revision+1 WHERE `+identity, append(key, in.Revision, digest)...)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE `+s.table+` SET producer_revision=$7,producer_hash=$8,
kind=$9,data=$10,created_at=$11,status=$12,severity=$13,action_requested=$14,source_subject=$15,
read_at=CASE WHEN withdrawn THEN NULL ELSE read_at END,
dismissed_at=CASE WHEN withdrawn THEN NULL ELSE dismissed_at END,
withdrawn=false,resolved_at=NULL,updated_at=clock_timestamp(),revision=revision+1 WHERE `+identity,
			append(key, in.Revision, digest, in.Kind, in.Data, in.CreatedAt, in.Status, in.Severity, in.ActionRequested, in.Origin.Subject)...)
		return err
	}
	createdAt, data := in.CreatedAt, in.Data
	if in.Withdrawn {
		createdAt, data = time.Now().UTC(), json.RawMessage(`{}`)
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+s.table+`(scope,audience,recipient,source,source_scope,source_id,
id,kind,data,created_at,status,severity,action_requested,source_subject,visibility,app_id,producer_revision,producer_hash,withdrawn)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		append(key, rand.Text(), in.Kind, data, createdAt, in.Status, in.Severity, in.ActionRequested, in.Origin.Subject, in.Visibility, in.AppID, in.Revision, digest, in.Withdrawn)...)
	return err
}
