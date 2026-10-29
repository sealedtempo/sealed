package policy

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sealedtempo/sealed/runtime/composer/cjson"
)

// The shared CJSON vectors (INTERFACES section 1) are owned by the composer.
// Egress checks configs with the composer's cjson package; this test keeps
// CheckCanonical in step with the vectors, so egress never refuses a config
// the composer considers canonical, and never accepts one it does not.
const sharedVectors = "../../composer/testdata/cjson/vectors.json"

type cjsonVector struct {
	In    string `json:"in"`
	Out   string `json:"out"`
	Error string `json:"error"`
}

func TestSharedCJSONVectors(t *testing.T) {
	data, err := os.ReadFile(sharedVectors)
	if err != nil {
		t.Fatalf("shared vectors: %v", err)
	}
	var vectors []cjsonVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vectors {
		if v.Error != "" {
			if err := CheckCanonical([]byte(v.In)); err == nil {
				t.Errorf("vector %d (%s): %q accepted", i, v.Error, v.In)
			}
			continue
		}
		if err := CheckCanonical([]byte(v.Out)); err != nil {
			t.Errorf("vector %d: canonical output %q rejected: %v", i, v.Out, err)
		}
		if v.In != v.Out {
			if err := CheckCanonical([]byte(v.In)); err == nil {
				t.Errorf("vector %d: non-canonical input %q accepted", i, v.In)
			}
		}
		got, err := cjson.Canonicalize([]byte(v.In))
		if err != nil || string(got) != v.Out {
			t.Errorf("vector %d: canonicalize %q = %q, %v; want %q", i, v.In, got, err, v.Out)
		}
	}
}

// TestEncodeCanonicalIsComposerCJSON pins that egress tooling produces the
// composer's bytes for the same value.
func TestEncodeCanonicalIsComposerCJSON(t *testing.T) {
	cfg := sampleConfig()
	a, err := EncodeCanonical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cjson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("EncodeCanonical %s differs from cjson.Marshal %s", a, b)
	}
	if err := CheckCanonical(a); err != nil {
		t.Fatal(err)
	}
}
