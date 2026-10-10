package errmodel

import "time"

// StepUp reports whether err is step_up_required and, if so, the sign-in
// age it asks for (its max_age_seconds) and its metadata (the account's
// step-up methods).
func StepUp(err error) (maxAge time.Duration, metadata map[string]any, ok bool) {
	e := As(err)
	if e == nil || e.code != CodeStepUpRequired {
		return 0, nil, false
	}
	metadata = e.Metadata()
	switch v := metadata["max_age_seconds"].(type) {
	case int64:
		maxAge = time.Duration(v) * time.Second
	case int:
		maxAge = time.Duration(v) * time.Second
	}
	return maxAge, metadata, true
}
