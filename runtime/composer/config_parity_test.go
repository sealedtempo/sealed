package composer

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The config parity table: the configs ParseConfig plus validateComposable
// accept and refuse, which @sealed/core's sealedConfigSchema must accept and
// refuse alike (packages/core/test/configParity.test.ts reads the same file).
// Each case starts from base, sets values at dotted paths (sorted by path, so
// a parent is set before its children; a number segment indexes a list) and
// then deletes paths; or it is raw text; pad appends spaces up to that many
// bytes. A value {"$gen": "h{i}.example.com:443", "count": n} is a list of n
// strings with {i} replaced by 0 to n-1. Valid cases carry the configHash the
// composer computes; go test -run TestConfigParity -update-parity rewrites
// those and the base's composerVersion.
const parityTablePath = "testdata/config-parity.json"

var updateParity = flag.Bool("update-parity", false, "rewrite configHash values and composerVersion in "+parityTablePath)

type parityTable struct {
	Comment []string        `json:"comment"`
	Base    json.RawMessage `json:"base"`
	Cases   []parityCase    `json:"cases"`
}

type parityCase struct {
	Name   string                     `json:"name"`
	Set    map[string]json.RawMessage `json:"set,omitempty"`
	Delete []string                   `json:"delete,omitempty"`
	Raw    *string                    `json:"raw,omitempty"`
	Pad    int                        `json:"pad,omitempty"`
	Valid  bool                       `json:"valid"`
	// TSValid is set where the TypeScript schema deliberately differs, with Why.
	TSValid    *bool  `json:"tsValid,omitempty"`
	Why        string `json:"why,omitempty"`
	Field      string `json:"field,omitempty"`
	ConfigHash string `json:"configHash,omitempty"`
}

func decodeNumbers(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// expandGen turns every {"$gen": pattern, "count": n} in v into a list of n
// copies of the pattern (a string, or an object of strings) with {i}
// replaced by the index and {ii} by the index in two digits.
func expandGen(v any) any {
	switch x := v.(type) {
	case []any:
		for i := range x {
			x[i] = expandGen(x[i])
		}
		return x
	case map[string]any:
		if _, ok := x["$gen"]; !ok {
			for k := range x {
				x[k] = expandGen(x[k])
			}
			return x
		}
	default:
		return v
	}
	m := v.(map[string]any)
	pat := m["$gen"]
	n, _ := strconv.Atoi(string(m["count"].(json.Number)))
	out := make([]any, n)
	for i := range out {
		fill := func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(s, "{ii}", fmt.Sprintf("%02d", i)), "{i}", strconv.Itoa(i))
		}
		switch p := pat.(type) {
		case string:
			out[i] = fill(p)
		case map[string]any:
			obj := map[string]any{}
			for k, x := range p {
				obj[k] = fill(x.(string))
			}
			out[i] = obj
		}
	}
	return out
}

// setPath sets (or with del, removes) the value at a dotted path.
func setPath(root any, path string, val any, del bool) error {
	segs := strings.Split(path, ".")
	cur := root
	for i, seg := range segs {
		last := i == len(segs)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				if del {
					delete(node, seg)
				} else {
					node[seg] = val
				}
				return nil
			}
			next, ok := node[seg]
			if !ok {
				return fmt.Errorf("%s: no %q", path, seg)
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return fmt.Errorf("%s: bad index %q", path, seg)
			}
			if last {
				if del {
					return fmt.Errorf("%s: cannot delete a list element", path)
				}
				node[idx] = val
				return nil
			}
			cur = node[idx]
		default:
			return fmt.Errorf("%s: %q is not inside an object or list", path, seg)
		}
	}
	return nil
}

func (c parityCase) document(base json.RawMessage) ([]byte, error) {
	var out []byte
	if c.Raw != nil {
		out = []byte(*c.Raw)
	} else {
		doc, err := decodeNumbers(base)
		if err != nil {
			return nil, err
		}
		paths := make([]string, 0, len(c.Set))
		for p := range c.Set {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			v, err := decodeNumbers(c.Set[p])
			if err != nil {
				return nil, fmt.Errorf("set %s: %v", p, err)
			}
			if err := setPath(doc, p, expandGen(v), false); err != nil {
				return nil, err
			}
		}
		for _, p := range c.Delete {
			if err := setPath(doc, p, nil, true); err != nil {
				return nil, err
			}
		}
		if out, err = json.Marshal(doc); err != nil {
			return nil, err
		}
	}
	if c.Pad > 0 {
		if len(out) > c.Pad {
			return nil, fmt.Errorf("document is %d bytes, more than pad %d", len(out), c.Pad)
		}
		out = append(out, bytes.Repeat([]byte(" "), c.Pad-len(out))...)
	}
	return out, nil
}

// parityVerdict is what the composer decides about a config on its own.
func parityVerdict(raw []byte) (*Config, error) {
	c, err := ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	return c, c.validateComposable()
}

func TestConfigParity(t *testing.T) {
	raw, err := os.ReadFile(parityTablePath)
	if err != nil {
		t.Fatal(err)
	}
	var table parityTable
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(table.Base, &base); err != nil {
		t.Fatal(err)
	}
	if base["composerVersion"] != Version {
		if !*updateParity {
			t.Fatalf("%s: base composerVersion %v, the composer is %s; run go test -run TestConfigParity -update-parity", parityTablePath, base["composerVersion"], Version)
		}
		table.Base = bytes.Replace(table.Base, []byte(fmt.Sprintf(`"composerVersion": %q`, base["composerVersion"])), []byte(fmt.Sprintf(`"composerVersion": %q`, Version)), 1)
	}
	names := map[string]bool{}
	valid, invalid := 0, 0
	for i := range table.Cases {
		c := &table.Cases[i]
		if names[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		names[c.Name] = true
		if c.TSValid != nil && (*c.TSValid == c.Valid || c.Why == "") {
			t.Errorf("%s: tsValid must differ from valid and carry why", c.Name)
		}
		doc, err := c.document(table.Base)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		cfg, err := parityVerdict(doc)
		switch {
		case c.Valid && err != nil:
			t.Errorf("%s: refused: %v", c.Name, err)
		case !c.Valid && err == nil:
			t.Errorf("%s: accepted", c.Name)
		case !c.Valid:
			invalid++
			if c.Field != "" && !strings.Contains(err.Error(), c.Field) {
				t.Errorf("%s: error %q does not name %s", c.Name, err, c.Field)
			}
		default:
			valid++
			h, err := cfg.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if *updateParity {
				c.ConfigHash = h.Hex()
			} else if c.ConfigHash != h.Hex() {
				t.Errorf("%s: configHash %s, the table says %q (go test -run TestConfigParity -update-parity)", c.Name, h.Hex(), c.ConfigHash)
			}
		}
		if !c.Valid && c.ConfigHash != "" {
			t.Errorf("%s: an invalid case has no configHash", c.Name)
		}
	}
	if valid < 40 || invalid < 100 {
		t.Errorf("only %d valid and %d invalid cases", valid, invalid)
	}
	if *updateParity && !t.Failed() {
		if err := os.WriteFile(parityTablePath, formatParityTable(t, table), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// formatParityTable writes the base indented and one case per line.
func formatParityTable(t *testing.T, table parityTable) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := func(v any) string {
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		if err := e.Encode(v); err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(buf.String(), "\n")
	}
	b.WriteString("{\n  \"comment\": [\n")
	for i, line := range table.Comment {
		b.WriteString("    " + enc(line))
		if i < len(table.Comment)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ],\n  \"base\": ")
	var base bytes.Buffer
	if err := json.Indent(&base, table.Base, "  ", "  "); err != nil {
		t.Fatal(err)
	}
	b.Write(base.Bytes())
	b.WriteString(",\n  \"cases\": [\n")
	for i, c := range table.Cases {
		b.WriteString("    " + enc(c))
		if i < len(table.Cases)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ]\n}\n")
	return b.Bytes()
}
