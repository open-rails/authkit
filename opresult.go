package authkit

import (
	"encoding/json"
)

// OpResult is the per-item outcome of a batch mutation (#219/#222): batch
// writes return one OpResult per requested ID so partial failure is
// expressible — a bare single error on a bulk write would hide which item
// failed. Err == nil means the item succeeded.
//
// As JSON, Err marshals as its wire code (#197), so errors.Is against authkit
// sentinels survives the round-trip; a non-Error (or a 500) degrades to
// internal_error.
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
		if e := AsError(r.Err); e != nil && e.Status != 500 {
			w.Error = string(e.Code)
		} else {
			w.Error = string(CodeInternalError)
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
		r.Err = E(Code(w.Error))
	}
	return nil
}
