package policy

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sealedtempo/sealed/runtime/composer/cjson"
)

// The egress config is measured, so the bytes egress reads must be the
// canonical JSON (INTERFACES section 1) the composer hashed. Egress uses the
// composer's own CJSON package (D-006), so both sides agree by construction:
// re-encoding the parsed document and comparing bytes rejects duplicate
// keys, floats, whitespace and non-canonical escapes in one pass.

// decodeTree parses JSON with the strict CJSON parser into maps, slices,
// strings, bools, int64 and nil, rejecting trailing data, duplicate keys,
// floats, integers beyond 2^53 and invalid UTF-8.
func decodeTree(data []byte) (any, error) {
	tree, err := cjson.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config is not valid canonical-profile JSON: %w", err)
	}
	return tree, nil
}

// CheckCanonical returns nil when data is exactly the canonical JSON encoding
// of the document it contains.
func CheckCanonical(data []byte) error {
	canon, err := cjson.Canonicalize(data)
	if err != nil {
		return fmt.Errorf("config is not canonical JSON: %w", err)
	}
	if !bytes.Equal(canon, data) {
		return errors.New("config is not canonical JSON (sorted keys, no whitespace, no duplicate keys, no trailing newline)")
	}
	return nil
}

// EncodeCanonical returns the canonical JSON encoding of v after a standard
// JSON round trip. Tests and tooling use it to produce configs egress accepts.
func EncodeCanonical(v any) ([]byte, error) {
	return cjson.Marshal(v)
}
