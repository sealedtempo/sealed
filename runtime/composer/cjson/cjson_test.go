package cjson

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vector struct {
	In    string `json:"in"`
	Out   string `json:"out"`
	Error string `json:"error"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../testdata/cjson/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

func TestSharedVectors(t *testing.T) {
	for i, v := range loadVectors(t) {
		out, err := Canonicalize([]byte(v.In))
		if v.Error != "" {
			if err == nil {
				t.Errorf("vector %d %q: want error %q, got %q", i, v.In, v.Error, out)
				continue
			}
			if !strings.Contains(err.Error(), v.Error) || !IsKind(err, v.Error) {
				t.Errorf("vector %d %q: want error kind %q, got %v", i, v.In, v.Error, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("vector %d %q: unexpected error %v", i, v.In, err)
			continue
		}
		if string(out) != v.Out {
			t.Errorf("vector %d:\n in  %q\n got %q\nwant %q", i, v.In, out, v.Out)
		}
		// Canonical output must be a fixed point.
		again, err := Canonicalize(out)
		if err != nil || string(again) != string(out) {
			t.Errorf("vector %d: not idempotent: %q -> %q (%v)", i, out, again, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		`{"a":1}x`:             KindInvalidJSON,
		`[1,]`:                 KindInvalidJSON,
		`{"a":01}`:             KindInvalidJSON,
		`"\ud800"`:             KindInvalidJSON,
		`"\udc00\ud800"`:       KindInvalidJSON,
		"\"\x01\"":             KindInvalidJSON,
		"\"\xff\"":             KindInvalidUTF8,
		`-9007199254740992`:    KindIntRange,
		`99999999999999999999`: KindIntRange,
		`1.0`:                  KindFloat,
		`-0.0`:                 KindFloat,
		`{"a":{"b":1,"b":2}}`:  KindDuplicateKey,
		`tru`:                  KindInvalidJSON,
		``:                     KindInvalidJSON,
		`"\x"`:                 KindInvalidJSON,
	}
	for in, kind := range cases {
		if _, err := Canonicalize([]byte(in)); !IsKind(err, kind) {
			t.Errorf("%q: want %s, got %v", in, kind, err)
		}
	}
}

func TestEscapes(t *testing.T) {
	got, err := Encode(map[string]any{"k": "\b\f\n\r\t\x00\x1f\x7f\"\\/<>&é"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"\b\f\n\r\t\u0000\u001f` + "\x7f" + `\"\\/<>&é"}`
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMarshalStructsAndMaps(t *testing.T) {
	type inner struct {
		Z string `json:"z"`
		A []int  `json:"a"`
	}
	type outer struct {
		Name  string            `json:"name"`
		Inner inner             `json:"inner"`
		Tags  map[string]string `json:"tags"`
		Skip  string            `json:"skip,omitempty"`
	}
	got, err := Marshal(outer{Name: "<x>", Inner: inner{Z: "z", A: []int{3, 1}}, Tags: map[string]string{"b": "2", "a": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"inner":{"a":[3,1],"z":"z"},"name":"<x>","tags":{"a":"1","b":"2"}}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if _, err := Marshal(map[string]any{"f": 1.5}); !IsKind(err, KindFloat) {
		t.Fatalf("float: %v", err)
	}
	if _, err := Marshal(map[string]any{"n": int64(1 << 53)}); !IsKind(err, KindIntRange) {
		t.Fatalf("range: %v", err)
	}
	if _, err := Marshal(map[string]any{"ké": 1}); !IsKind(err, KindNonASCIIKey) {
		t.Fatalf("key: %v", err)
	}
}

func TestMapOrderIndependence(t *testing.T) {
	build := func(order []string) map[string]any {
		m := map[string]any{}
		for i, k := range order {
			m[k] = map[string]any{"v": i * 0, "k": k}
		}
		return m
	}
	a, _ := Marshal(build([]string{"x", "a", "m", "B", "_"}))
	b, _ := Marshal(build([]string{"_", "B", "m", "a", "x"}))
	if string(a) != string(b) {
		t.Fatalf("%s != %s", a, b)
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{`{"a":[1,2,{"b":null}]}`, `"x\u00e9"`, `[true,false]`, `{"b":1,"a":2}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Canonicalize(in)
		if err != nil {
			return
		}
		again, err := Canonicalize(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("not a fixed point: %q -> %q (%v)", out, again, err)
		}
		if !json.Valid(out) {
			t.Fatalf("invalid JSON output %q", out)
		}
	})
}
