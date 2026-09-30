package httpapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/wireform"
)

// writeJSON is the one success writer. The body goes out in wire form: every
// time in UTC, every list [] and every map {} rather than null.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wireform.Of(v))
}

// decodeQuery reads the query string into dst, a pointer to a struct whose
// `query` tags name the parameters: a string takes the value, a *int the
// integer (nil when absent), a []string every value. Embedded structs
// contribute their fields. A malformed integer is 400 invalid_request on its
// param.
func decodeQuery(r *http.Request, dst any) error {
	q := r.URL.Query()
	var fill func(v reflect.Value) error
	fill = func(v reflect.Value) error {
		for i := range v.NumField() {
			f, field := v.Type().Field(i), v.Field(i)
			if f.Anonymous {
				if err := fill(field); err != nil {
					return err
				}
				continue
			}
			name := f.Tag.Get("query")
			if name == "" {
				continue
			}
			value := strings.TrimSpace(q.Get(name))
			switch field.Interface().(type) {
			case string:
				field.SetString(value)
			case *int:
				if value == "" {
					continue
				}
				n, err := strconv.Atoi(value)
				if err != nil {
					return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam(name))
				}
				field.Set(reflect.ValueOf(&n))
			case []string:
				var values []string
				for _, value := range q[name] {
					values = append(values, strings.TrimSpace(value))
				}
				field.Set(reflect.ValueOf(values))
			default:
				panic("httpapi: no query decoding for " + f.Type.String())
			}
		}
		return nil
	}
	return fill(reflect.ValueOf(dst).Elem())
}

// Page is the one page parser: an opaque cursor, and a limit of 1 to
// iam.MaxPageLimit (default iam.DefaultPageLimit). Any other limit is 400
// invalid_request on param limit.
func (q PageQuery) Page() (iam.PageRequest, error) {
	page := iam.PageRequest{Cursor: q.Cursor}
	if q.Limit == nil {
		return page, nil
	}
	if *q.Limit < 1 || *q.Limit > iam.MaxPageLimit {
		return page, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("limit"))
	}
	page.Limit = *q.Limit
	return page, nil
}

// readQuery decodes a route's query string, answering 400 for a malformed
// one.
func readQuery(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := decodeQuery(r, dst); err != nil {
		writeError(w, err)
		return false
	}
	return true
}

// readPage reads a list route's ?cursor= and ?limit=, answering 400 for a
// bad limit.
func readPage(w http.ResponseWriter, r *http.Request) (iam.PageRequest, bool) {
	var q PageQuery
	if !readQuery(w, r, &q) {
		return iam.PageRequest{}, false
	}
	page, err := q.Page()
	if err != nil {
		writeError(w, err)
		return page, false
	}
	return page, true
}

// list answers one page of items.
func list[T any](w http.ResponseWriter, page iam.ListPage[T]) {
	writeJSON(w, http.StatusOK, page)
}

// all answers a bounded list as one page.
func all[T any](w http.ResponseWriter, items []T) {
	writeJSON(w, http.StatusOK, iam.ListPage[T]{Items: items})
}
