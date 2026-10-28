package cjson

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	In    string `json:"in"`
	Out   string `json:"out"`
	Error string `json:"error"`
}

var errorNames = map[string]error{
	"float":                ErrFloat,
	"integer out of range": ErrIntegerRange,
	"duplicate key":        ErrDuplicateKey,
	"non-ASCII key":        ErrNonASCIIKey,
	"invalid JSON":         ErrInvalidJSON,
}

// TestSharedVectors runs the vectors shared with runtime/composer/cjson and @sealed/core/cjson.
func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "runtime", "composer", "testdata", "cjson", "vectors.json"))
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		got, err := Canonicalize([]byte(v.In))
		if v.Error != "" {
			want, ok := errorNames[v.Error]
			if !ok {
				t.Fatalf("unknown error class %q", v.Error)
			}
			if !errors.Is(err, want) {
				t.Errorf("Canonicalize(%q) error = %v, want %v", v.In, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("Canonicalize(%q): %v", v.In, err)
			continue
		}
		if string(got) != v.Out {
			t.Errorf("Canonicalize(%q) = %q, want %q", v.In, got, v.Out)
		}
	}
}

func TestRejectsTrailingDataAndInvalidUTF8(t *testing.T) {
	for _, in := range []string{`{"a":1} {}`, `[1]x`, "\"\xff\""} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("Canonicalize(%q) accepted", in)
		}
	}
}

func TestMarshalStruct(t *testing.T) {
	got, err := Marshal(struct {
		Z string `json:"z"`
		A []int  `json:"a"`
		H string `json:"h"`
	}{Z: "x", A: []int{2, 1}, H: "<&>"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":[2,1],"h":"<&>","z":"x"}`; string(got) != want {
		t.Fatalf("Marshal = %s, want %s", got, want)
	}
}

func TestIdempotent(t *testing.T) {
	in := []byte(`{"b":[{"y":1,"x":"\u0007"}],"a":"café"}`)
	once, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Canonicalize(once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent: %s vs %s", once, twice)
	}
}
