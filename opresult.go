package authkit

import (
	"encoding/json"
	"errors"
)

// OpResult is the per-item outcome of a batch mutation (#219/#222): batch
// writes return one OpResult per requested ID so partial failure is
// expressible — a bare single error on a bulk write would hide which item
// failed. Err == nil means the item succeeded.
//
// Over the remote transport Err marshals as its sentinel wire code (#197), so
// errors.Is against authkit sentinels survives the round-trip; a non-sentinel
// error degrades to an opaque code string.
type OpResult struct {
	ID  string
	Err error
}

type opResultWire struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

func (r OpResult) MarshalJSON() ([]byte, error) {
	w := opResultWire{ID: r.ID}
	if r.Err != nil {
		if code := CodeForError(r.Err); code != "" {
			w.Error = code
		} else {
			w.Error = "internal_error"
		}
	}
	return json.Marshal(w)
}

func (r *OpResult) UnmarshalJSON(b []byte) error {
	var w opResultWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	r.ID = w.ID
	r.Err = nil
	if w.Error != "" {
		if sentinel := ErrorForCode(w.Error); sentinel != nil {
			r.Err = sentinel
		} else {
			r.Err = errors.New(w.Error)
		}
	}
	return nil
}
