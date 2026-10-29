package strictjson

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// fuzzDoc has every shape the verifier decodes with strictjson: nested and
// pointer structs, slices of structs, maps, raw messages, an untagged field,
// an embedded struct and a skipped field.
type fuzzDoc struct {
	Schema   string            `json:"schema"`
	ChainID  uint64            `json:"chainId"`
	Apps     []inner           `json:"apps"`
	Nested   *inner            `json:"nested,omitempty"`
	Config   json.RawMessage   `json:"config"`
	Env      map[string]string `json:"env"`
	Lists    map[string][]int  `json:"lists"`
	Debug    bool              `json:"debug"`
	Any      any               `json:"any"`
	Untagged string
	Skipped  string `json:"-"`
	Embedded
}

// caseSensitive reports whether v holds exactly what a case-sensitive,
// duplicate-free reader (JSON.parse, CJSON) finds in the generic value g:
// every field equals the value under its exact JSON name, or is zero when the
// name is absent. A mismatch means encoding/json filled a field from a key
// spelled differently, which strictjson exists to refuse.
func caseSensitive(g any, v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer:
		if g == nil {
			return v.IsNil()
		}
		return !v.IsNil() && caseSensitive(g, v.Elem())
	case reflect.Struct:
		obj, ok := g.(map[string]any)
		if !ok {
			return g == nil && v.IsZero()
		}
		return structMatches(obj, v)
	case reflect.Map:
		obj, ok := g.(map[string]any)
		if !ok {
			return g == nil && v.IsNil()
		}
		if v.Len() != len(obj) {
			return false
		}
		for k, gv := range obj {
			fv := v.MapIndex(reflect.ValueOf(k))
			if !fv.IsValid() || !caseSensitive(gv, fv) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if v.Type() == reflect.TypeOf(json.RawMessage(nil)) {
			var rv any
			if v.Len() == 0 {
				return g == nil
			}
			dec := json.NewDecoder(bytes.NewReader(v.Bytes()))
			dec.UseNumber()
			return dec.Decode(&rv) == nil && reflect.DeepEqual(rv, g)
		}
		list, ok := g.([]any)
		if !ok {
			return g == nil && v.IsNil()
		}
		if v.Len() != len(list) {
			return false
		}
		for i := range list {
			if !caseSensitive(list[i], v.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Interface:
		a, _ := json.Marshal(v.Interface())
		b, _ := json.Marshal(g)
		var x, y any
		return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
	case reflect.String:
		s, ok := g.(string)
		return ok && s == v.String() || g == nil && v.String() == ""
	case reflect.Bool:
		b, ok := g.(bool)
		return ok && b == v.Bool() || g == nil && !v.Bool()
	case reflect.Uint64, reflect.Uint32, reflect.Int, reflect.Int64:
		n, ok := g.(json.Number)
		if !ok {
			return g == nil && v.IsZero()
		}
		if v.CanInt() {
			return n.String() == strconv.FormatInt(v.Int(), 10)
		}
		return n.String() == strconv.FormatUint(v.Uint(), 10)
	}
	return true
}

func structMatches(obj map[string]any, v reflect.Value) bool {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			if !structMatches(obj, v.Field(i)) {
				return false
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		gv, present := obj[name]
		if !present {
			if !v.Field(i).IsZero() {
				return false
			}
			continue
		}
		if !caseSensitive(gv, v.Field(i)) {
			return false
		}
	}
	return true
}

// FuzzUnmarshal: whenever Unmarshal accepts a document, the decoded struct is
// what a case-sensitive reader sees in it, and no object in it has two keys
// that are equal under case folding.
func FuzzUnmarshal(f *testing.F) {
	for _, s := range []string{
		`{"schema":"s","chainId":4217,"apps":[{"id":"crm"}],"nested":{"id":"x"},"config":{"a":[1,{"b":null}]},"env":{"K":"v"},"lists":{"a":[1,2]},"debug":true,"any":{"x":[1.5]},"Untagged":"u","salt":"s","unknown":{"x":1}}`,
		`{"Schema":"s"}`, `{"schema":"a","SCHEMA":"b"}`, `{"ſalt":"x"}`, `{"Key":1}`, `{"İd":1}`, `{"apps":[{"ıd":"crm"}]}`,
		`{"nested":null,"config":null,"env":null,"apps":null}`, `{"chainId":-1}`, `{"chainId":1e2}`, `[1]`, `{"a":1} x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var d fuzzDoc
		if err := Unmarshal(raw, &d); err != nil {
			return
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var g any
		if err := dec.Decode(&g); err != nil {
			t.Fatalf("accepted document encoding/json cannot decode: %v", err)
		}
		if !caseSensitive(g, reflect.ValueOf(d)) {
			t.Fatalf("decoded %+v is not what a case-sensitive reader sees in %s", d, raw)
		}
		if err := CheckKeys(raw, nil); err != nil {
			t.Fatalf("accepted with a type but refused without one: %v", err)
		}
	})
}
