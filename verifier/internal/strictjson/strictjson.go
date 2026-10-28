// Package strictjson decodes JSON the way a case-sensitive consumer reads it. encoding/json matches object keys to
// struct fields case-insensitively and keeps the last of duplicate keys, while the in-VM agent and the TypeScript
// services (JSON.parse) are case-sensitive, and CJSON hashes "customer" and "Customer" as two keys. Refusing such
// documents means every consumer reads the same fields from the same measured bytes.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
)

// Unmarshal is json.Unmarshal after CheckKeys(raw, type of v).
func Unmarshal(raw []byte, v any) error {
	if err := CheckKeys(raw, reflect.TypeOf(v)); err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// CheckKeys rejects, in every object of raw, two keys equal under Unicode case folding (exact duplicates
// included), and, where t maps the object to a struct, a key that matches a field only up to case.
func CheckKeys(raw []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkKeys(dec, t, "$"); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data after the JSON value")
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// elemType strips pointers; nil means "any JSON" (no field names to enforce).
func elemType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType || (t != nil && t.Kind() == reflect.Interface) {
		return nil
	}
	return t
}

type jsonField struct {
	name string
	typ  reflect.Type
}

// jsonFields maps the folded JSON name of each field of struct t (embedded structs flattened) to the field.
func jsonFields(t reflect.Type, out map[string]jsonField) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && elemType(f.Type) != nil && elemType(f.Type).Kind() == reflect.Struct {
			jsonFields(elemType(f.Type), out)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[foldKey(name)] = jsonField{name: name, typ: f.Type}
	}
}

func walkKeys(dec *json.Decoder, t reflect.Type, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON at %s: %v", path, err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	t = elemType(t)
	switch d {
	case '{':
		var fields map[string]jsonField
		var mapElem reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			fields = map[string]jsonField{}
			jsonFields(t, fields)
		} else if t != nil && t.Kind() == reflect.Map {
			mapElem = t.Elem()
		}
		seen := map[string]string{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON at %s: %v", path, err)
			}
			key := kt.(string)
			folded := foldKey(key)
			if prev, dup := seen[folded]; dup {
				return fmt.Errorf("%s: keys %q and %q collide (JSON keys are case-sensitive here)", path, prev, key)
			}
			seen[folded] = key
			sub := mapElem
			if fields != nil {
				f, known := fields[folded]
				if known && f.name != key {
					return fmt.Errorf("%s: key %q must be spelled %q", path, key, f.name)
				}
				sub = f.typ // nil for unknown keys
			}
			if err := walkKeys(dec, sub, path+"."+key); err != nil {
				return err
			}
		}
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := walkKeys(dec, elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// foldKey maps each rune to the smallest rune of its case-folding orbit, so two keys are equal under
// strings.EqualFold exactly when their folded forms are equal.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		lo := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			lo = min(lo, f)
		}
		b.WriteRune(lo)
	}
	return b.String()
}
