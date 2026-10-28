package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// The shared CJSON vectors (INTERFACES section 1) are owned by the composer.
// Egress keeps its own checker, so it must agree with them exactly:
// otherwise egress would refuse configs the composer considers canonical.
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
		tree, err := decodeTree([]byte(v.In))
		if err != nil {
			t.Errorf("vector %d: decode %q: %v", i, v.In, err)
			continue
		}
		var buf bytes.Buffer
		if err := encodeCanonical(&buf, tree); err != nil || buf.String() != v.Out {
			t.Errorf("vector %d: encode %q = %q, %v; want %q", i, v.In, buf.String(), err, v.Out)
		}
	}
}
