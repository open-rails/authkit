package scim

import (
	"encoding/json"
	"errors"
	"strings"
)

// Filter is the filter subset AuthKit's service provider answers: equality
// on id, userName or emails.value, joined by "or". A user matches when it
// matches any term.
type Filter struct {
	IDs, UserNames, Emails []string
}

// ErrInvalidFilter is a filter outside the subset; its message is the
// response's detail.
var ErrInvalidFilter = errors.New("scim: invalid filter")

type filterError string

func (e filterError) Error() string        { return string(e) }
func (e filterError) Is(target error) bool { return target == ErrInvalidFilter }

// ParseFilter parses expr: `attr eq "value"` terms joined by "or",
// attribute names and operators matched without regard to case
// (RFC 7644 §3.4.2.2).
func ParseFilter(expr string) (Filter, error) {
	var f Filter
	rest := strings.TrimSpace(expr)
	if rest == "" {
		return f, filterError("the filter is empty")
	}
	for {
		attr, after, ok := cutField(rest)
		if !ok {
			return Filter{}, filterError("expected an attribute")
		}
		op, after, ok := cutField(after)
		if !ok || !strings.EqualFold(op, "eq") {
			return Filter{}, filterError("only the eq operator is supported")
		}
		value, after, err := cutString(after)
		if err != nil {
			return Filter{}, err
		}
		switch strings.ToLower(attr) {
		case "id":
			f.IDs = append(f.IDs, value)
		case "username":
			f.UserNames = append(f.UserNames, value)
		case "emails.value", "emails":
			f.Emails = append(f.Emails, value)
		default:
			return Filter{}, filterError("filtering on " + attr + " is not supported (id, userName, emails.value)")
		}
		rest = strings.TrimSpace(after)
		if rest == "" {
			return f, nil
		}
		join, after, _ := cutField(rest)
		if !strings.EqualFold(join, "or") {
			return Filter{}, filterError("terms may only be joined by or")
		}
		rest = strings.TrimSpace(after)
	}
}

// cutField splits off the next space-delimited word.
func cutField(s string) (word, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	word, rest, _ = strings.Cut(s, " ")
	return word, rest, word != ""
}

// cutString splits off a leading JSON string.
func cutString(s string) (string, string, error) {
	s = strings.TrimLeft(s, " ")
	if !strings.HasPrefix(s, `"`) {
		return "", "", filterError("the value must be a quoted string")
	}
	escaped := false
	for i := 1; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == '"':
			var value string
			if err := json.Unmarshal([]byte(s[:i+1]), &value); err != nil {
				return "", "", filterError("the value is not a valid string")
			}
			return value, s[i+1:], nil
		}
	}
	return "", "", filterError("the value's string is not closed")
}
