package composer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
	"go.yaml.in/yaml/v3"
)

// decodeYAML parses exactly one YAML document into a JSON-compatible tree of
// nil, bool, int64, string, []any and map[string]any. Anchors, aliases and
// merge keys are resolved by the YAML decoder. Floats, non-string keys,
// out-of-range integers, binary and multiple documents are rejected, because
// every value ends up in a hashed canonical-JSON document.
func decodeYAML(file string, data []byte) (any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var raw any
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty document", file)
		}
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: exactly one YAML document is allowed", file)
	}
	v, err := normalizeYAML(raw, "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return v, nil
}

func normalizeYAML(v any, path string) (any, error) {
	switch t := v.(type) {
	case nil, bool, string:
		return t, nil
	case int:
		return checkInt(int64(t), path)
	case int64:
		return checkInt(t, path)
	case uint64:
		if t > cjson.MaxSafeInteger {
			return nil, fmt.Errorf("%s: integer out of range", displayPath(path))
		}
		return int64(t), nil
	case float64:
		return nil, fmt.Errorf("%s: floats are not allowed in hashed documents (write %v as a quoted string)", displayPath(path), t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			n, err := normalizeYAML(e, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for _, k := range sortedKeys(t) {
			n, err := normalizeYAML(t[k], joinPath(path, k))
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%s: mapping key %v is not a string", displayPath(path), k)
			}
			n, err := normalizeYAML(e, joinPath(path, ks))
			if err != nil {
				return nil, err
			}
			out[ks] = n
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: unsupported YAML value of type %T", displayPath(path), v)
	}
}

func checkInt(n int64, path string) (any, error) {
	if n > cjson.MaxSafeInteger || n < -cjson.MaxSafeInteger {
		return nil, fmt.Errorf("%s: integer out of range", displayPath(path))
	}
	return n, nil
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

func displayPath(p string) string {
	if p == "" {
		return "document"
	}
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// strictDecode converts a generic tree into a typed struct, rejecting fields
// the struct does not declare. Keys must match the json tags exactly:
// encoding/json alone would also accept "Customer" for "customer", which
// would give one document two spellings.
func strictDecode(v any, out any) error {
	if err := checkExactKeys(v, reflect.TypeOf(out), ""); err != nil {
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "json: "))
	}
	return nil
}

func checkExactKeys(v any, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return nil // type mismatches are reported by the decoder
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" || !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for _, k := range sortedKeys(obj) {
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("unknown field %q", joinPath(path, k))
			}
			if err := checkExactKeys(obj[k], ft, joinPath(path, k)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if obj, ok := v.(map[string]any); ok {
			for _, k := range sortedKeys(obj) {
				if err := checkExactKeys(obj[k], t.Elem(), joinPath(path, k)); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		if list, ok := v.([]any); ok {
			for i, e := range list {
				if err := checkExactKeys(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
