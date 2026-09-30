package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
)

// The wire model: every type a route's query, request or responses reach,
// read by reflection from the Go types the handlers marshal. Both outputs
// (OpenAPI and TypeScript) are rendered from it.

const module = "github.com/open-rails/authkit"

const (
	kindString   = httpapi.WireString
	kindInteger  = httpapi.WireInteger
	kindNumber   = httpapi.WireNumber
	kindBoolean  = httpapi.WireBoolean
	kindTime     = httpapi.WireTime
	kindBytes    = httpapi.WireBytes
	kindAny      = httpapi.WireAny
	kindOpaque   = httpapi.WireOpaque
	kindArray    = httpapi.WireArray
	kindMap      = httpapi.WireMap
	kindNullable = httpapi.WireNullable
	kindObject   = httpapi.WireObject
	kindPage     = httpapi.WirePage
)

var (
	classify = httpapi.KindOf
	pageItem = httpapi.PageItem
)

// field is one JSON member of an object.
type field struct {
	name     string
	t        reflect.Type
	optional bool // omitempty: absent when zero
}

func fieldsOf(t reflect.Type) []field {
	var out []field
	for _, f := range httpapi.Fields(t) {
		out = append(out, field{name: f.Name, t: f.Type, optional: f.Optional})
	}
	return out
}

// wireNames names the wire types whose Go name only reads well qualified by
// its package.
var wireNames = map[string]string{
	module + "/internal/naming.State":      "NamingState",
	module + "/internal/naming.Alias":      "NamingAlias",
	module + "/internal/naming.PolicyInfo": "NamingPolicy",
	module + "/iam.Event":                  "AuthKitEvent",
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

// contract is the catalog with every object its routes reach.
type contract struct {
	routes  []httpapi.RouteSpec
	objects map[string]*object
}

func newContract() (*contract, error) {
	c := &contract{routes: httpapi.Catalog(), objects: map[string]*object{}}
	// The committed changes Deps.OnEvent delivers: the payload of the
	// event vocabulary, kinds included.
	if err := c.reach(reflect.TypeFor[iam.Event](), false); err != nil {
		return nil, err
	}
	// Each error code's metadata shape.
	for _, meta := range httpapi.ErrorMetadata() {
		if err := c.reach(reflect.TypeOf(meta), false); err != nil {
			return nil, err
		}
	}
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

// enumValues are the string constants declared with an AuthKit string type,
// sorted: the values its wire field takes. None for any other type.
func enumValues(t reflect.Type) []string {
	if t.Kind() != reflect.String || t.Name() == "" || !strings.HasPrefix(t.PkgPath(), module) {
		return nil
	}
	dir := filepath.Join(repoRoot, strings.TrimPrefix(strings.TrimPrefix(t.PkgPath(), module), "/"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("contract: read %s: %v", dir, err))
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			panic(fmt.Sprintf("contract: parse %s: %v", name, err))
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != t.Name() {
					continue
				}
				for _, v := range vs.Values {
					if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						value, _ := strconv.Unquote(lit.Value)
						out = append(out, value)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
