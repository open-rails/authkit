package main

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/httpapi"
)

// The wire model: every type a route's query, request or responses reach,
// read by reflection from the Go types the handlers marshal. Both outputs
// (OpenAPI and TypeScript) are rendered from it.

const module = "github.com/open-rails/authkit"

type kind int

const (
	kindString kind = iota
	kindInteger
	kindNumber
	kindBoolean
	kindTime
	kindBytes
	kindAny    // arbitrary JSON
	kindOpaque // a JSON object defined outside AuthKit (WebAuthn options)
	kindArray
	kindMap
	kindNullable
	kindObject // a named AuthKit struct: a component
	kindPage   // iam.ListPage[T]
)

var (
	timeType          = reflect.TypeFor[time.Time]()
	rawMessageType    = reflect.TypeFor[json.RawMessage]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

func classify(t reflect.Type) kind {
	switch {
	case t == timeType:
		return kindTime
	case t == rawMessageType:
		return kindAny
	case isPage(t):
		return kindPage
	case t.Kind() == reflect.Pointer:
		return kindNullable
	case t.Implements(textMarshalerType):
		return kindString
	}
	switch t.Kind() {
	case reflect.String:
		return kindString
	case reflect.Bool:
		return kindBoolean
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return kindInteger
	case reflect.Float32, reflect.Float64:
		return kindNumber
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return kindBytes
		}
		return kindArray
	case reflect.Map:
		return kindMap
	case reflect.Interface:
		return kindAny
	case reflect.Struct:
		if !strings.HasPrefix(t.PkgPath(), module) {
			return kindOpaque
		}
		return kindObject
	}
	panic(fmt.Sprintf("contract: no wire form for %s", t))
}

// isPage reports whether t is iam.ListPage[T].
func isPage(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && t.PkgPath() == module+"/iam" && strings.HasPrefix(t.Name(), "ListPage[")
}

// pageItem is T of iam.ListPage[T].
func pageItem(t reflect.Type) reflect.Type { return t.Field(0).Type.Elem() }

// field is one JSON member of an object.
type field struct {
	name     string
	t        reflect.Type
	optional bool // omitempty: absent when zero
}

// wireNames names the wire types whose Go name only reads well qualified by
// its package.
var wireNames = map[string]string{
	module + "/internal/naming.State":      "NamingState",
	module + "/internal/naming.Alias":      "NamingAlias",
	module + "/internal/naming.PolicyInfo": "NamingPolicy",
}

// wireName is t's name on the wire.
func wireName(t reflect.Type) string {
	if name, ok := wireNames[t.PkgPath()+"."+t.Name()]; ok {
		return name
	}
	return t.Name()
}

// object is a named AuthKit struct.
type object struct {
	name   string
	t      reflect.Type
	fields []field
	input  bool // reached from a request body
	output bool // reached from a response body
}

// fieldsOf lists t's JSON members; embedded structs contribute theirs.
func fieldsOf(t reflect.Type) []field {
	var out []field
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			out = append(out, fieldsOf(f.Type)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, field{name: name, t: f.Type, optional: strings.Contains(","+opts+",", ",omitempty,")})
	}
	return out
}

// contract is the catalog with every object its routes reach.
type contract struct {
	routes  []httpapi.RouteSpec
	objects map[string]*object
}

func newContract() (*contract, error) {
	c := &contract{routes: httpapi.Catalog(), objects: map[string]*object{}}
	for _, r := range c.routes {
		if r.Request != nil {
			if err := c.reach(reflect.TypeOf(r.Request), true); err != nil {
				return nil, err
			}
		}
		for _, reply := range r.Responses {
			if reply.Body != nil {
				if err := c.reach(reflect.TypeOf(reply.Body), false); err != nil {
					return nil, err
				}
			}
		}
	}
	return c, nil
}

// reach records t and every object it reaches.
func (c *contract) reach(t reflect.Type, input bool) error {
	switch classify(t) {
	case kindNullable, kindArray, kindMap:
		return c.reach(t.Elem(), input)
	case kindPage:
		return c.reach(pageItem(t), input)
	case kindObject:
		name := wireName(t)
		if t.Name() == "" {
			return fmt.Errorf("contract: anonymous struct %s on the wire; name it", t)
		}
		o, seen := c.objects[name]
		if seen && o.t != t {
			return fmt.Errorf("contract: two wire types named %s: %s and %s", name, o.t, t)
		}
		if !seen {
			o = &object{name: name, t: t, fields: fieldsOf(t)}
			c.objects[name] = o
		}
		if input && o.input || !input && o.output {
			return nil
		}
		if input {
			o.input = true
		} else {
			o.output = true
		}
		for _, f := range o.fields {
			if err := c.reach(f.t, input); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *contract) sortedObjects() []*object {
	out := make([]*object, 0, len(c.objects))
	for _, o := range c.objects {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// queryParams lists a query struct's parameters: name and whether it repeats.
func queryParams(q any) []field {
	if q == nil {
		return nil
	}
	var out []field
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Anonymous {
				walk(f.Type)
				continue
			}
			if name := f.Tag.Get("query"); name != "" {
				out = append(out, field{name: name, t: f.Type})
			}
		}
	}
	walk(reflect.TypeOf(q))
	return out
}

// pathParams lists a route path's {wildcards}.
func pathParams(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, strings.TrimSuffix(strings.TrimPrefix(seg, "{"), "}"))
		}
	}
	return out
}

// fullPath is the route's path on a default mount: the JSON API beneath
// /api/v1, browser OIDC beneath /oidc, the issuer's own paths at the root.
func fullPath(r httpapi.RouteSpec) string {
	switch r.Surface {
	case httpapi.SurfaceAPI:
		return defaultAPIPath + r.Path
	case httpapi.SurfaceOIDC:
		return httpapi.OIDCPath + r.Path
	}
	return r.Path
}
