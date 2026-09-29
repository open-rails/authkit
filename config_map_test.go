package authkit

import (
	"reflect"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/jwtkit"
)

// TestConfigMapping sets every exported field of Config, Deps and
// MigrateOptions, recursively and one at a time, to a non-zero value and
// requires the internal settings to change: a field New drops fails here.
func TestConfigMapping(t *testing.T) {
	checkMapped(t, func(c Config) any { return c.settings() })
	checkMapped(t, func(d Deps) any { return d.engine() })
	checkMapped(t, func(o MigrateOptions) any { return o.engine() })
}

func checkMapped[T any](t *testing.T, mapping func(T) any) {
	t.Helper()
	fill := func(target string) (T, []string) {
		var v T
		var leaves []string
		fillLeaves(reflect.ValueOf(&v).Elem(), reflect.TypeFor[T]().Name(), target, &leaves)
		return v, leaves
	}
	base, leaves := fill("")
	require.NotEmpty(t, leaves)
	require.True(t, reflect.DeepEqual(mapping(base), mapping(base)), "the mapping must be deterministic")
	for _, leaf := range leaves {
		set, _ := fill(leaf)
		if reflect.DeepEqual(mapping(set), mapping(base)) {
			t.Errorf("%s does not reach the internal settings; map it in config_map.go", leaf)
		}
	}
}

// fillLeaves allocates every struct the walk descends into (pointers to root
// structs, struct slice elements and map values), records each leaf path and
// sets the one named target.
func fillLeaves(v reflect.Value, path, target string, leaves *[]string) {
	typ := v.Type()
	switch {
	case typ == reflect.TypeFor[*RiverOwnership](), typ == reflect.TypeFor[*Roles](), typ == reflect.TypeFor[iam.Persona]():
	case typ.Kind() == reflect.Struct:
		for i := range typ.NumField() {
			if f := typ.Field(i); f.IsExported() {
				fillLeaves(v.Field(i), path+"."+f.Name, target, leaves)
			}
		}
		return
	case typ.Kind() == reflect.Pointer && typ.Elem().Kind() == reflect.Struct && typ.Elem().PkgPath() == reflect.TypeFor[Config]().PkgPath():
		v.Set(reflect.New(typ.Elem()))
		fillLeaves(v.Elem(), path, target, leaves)
		return
	case typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Struct:
		v.Set(reflect.MakeSlice(typ, 1, 1))
		fillLeaves(v.Index(0), path+"[0]", target, leaves)
		return
	case typ.Kind() == reflect.Map && typ.Elem().Kind() == reflect.Struct:
		elem := reflect.New(typ.Elem()).Elem()
		fillLeaves(elem, path+"[k]", target, leaves)
		v.Set(reflect.MakeMap(typ))
		v.SetMapIndex(nonZero(typ.Key()), elem)
		return
	}
	*leaves = append(*leaves, path)
	if path == target {
		v.Set(nonZero(typ))
	}
}

type (
	emailStub        struct{ EmailSender }
	smsStub          struct{ SMSSender }
	entitlementsStub struct{ EntitlementsProvider }
	limiterStub      struct{ RateLimiter }
	identityStub     struct{ authprovider.Provider }
	redisStub        struct{ redis.UniversalClient }
)

// implementations supplies a value for each interface a field can hold.
var implementations = []any{
	jwtkit.StaticKeySource{}, emailStub{}, smsStub{}, entitlementsStub{},
	limiterStub{}, identityStub{}, redisStub{},
}

func nonZero(typ reflect.Type) reflect.Value {
	v := reflect.New(typ).Elem()
	switch typ.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(17)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(17)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.String:
		v.SetString("v17")
	case reflect.Slice:
		v = reflect.Append(v, nonZero(typ.Elem()))
	case reflect.Map:
		v.Set(reflect.MakeMap(typ))
		v.SetMapIndex(nonZero(typ.Key()), nonZero(typ.Elem()))
	case reflect.Pointer:
		if typ == reflect.TypeFor[*RiverOwnership]() {
			return reflect.ValueOf(RiverFromHost())
		}
		if typ == reflect.TypeFor[*Roles]() {
			roles := NewRoles()
			roles.Persona("v17")
			return reflect.ValueOf(roles)
		}
		v = reflect.New(typ.Elem())
		if typ.Elem().Kind() != reflect.Struct {
			v.Elem().Set(nonZero(typ.Elem()))
		}
	case reflect.Func:
		v = reflect.MakeFunc(typ, func([]reflect.Value) []reflect.Value {
			out := make([]reflect.Value, typ.NumOut())
			for i := range out {
				out[i] = reflect.Zero(typ.Out(i))
			}
			return out
		})
	case reflect.Interface:
		for _, impl := range implementations {
			if reflect.TypeOf(impl).Implements(typ) {
				v.Set(reflect.ValueOf(impl))
				return v
			}
		}
		panic("no test implementation of " + typ.String())
	case reflect.Struct:
		if typ == reflect.TypeFor[iam.Persona]() {
			return reflect.ValueOf(ident.Persona("v17"))
		}
		for i := range typ.NumField() {
			if typ.Field(i).IsExported() {
				v.Field(i).Set(nonZero(typ.Field(i).Type))
				return v
			}
		}
		panic("no exported field in " + typ.String())
	default:
		panic("unhandled kind " + typ.String())
	}
	return v
}
