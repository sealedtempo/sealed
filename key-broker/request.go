package keybroker

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/cjson"
)

// NonceResponse is the GET /v1/nonce body.
type NonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expiresAt"`
}

// ReleaseResponse is the 200 body of POST /v1/release.
type ReleaseResponse struct {
	StackHash    string `json:"stackHash"`
	DeploymentID string `json:"deploymentId"`
	Enc          string `json:"enc"`
	Ciphertext   string `json:"ciphertext"`
}

// Denial is the body of every non-200 answer of POST /v1/release.
type Denial struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail,omitempty"`
}

// ReleasePlaintext is what the release ciphertext decrypts to, encoded as CJSON (keys sorted).
type ReleasePlaintext struct {
	Secrets    map[string]map[string]string `json:"secrets"`
	DiskKey    string                       `json:"diskKey"`
	SignerSeed string                       `json:"signerSeed"`
}

// Request size bounds.
const (
	// MaxQuoteBytes is far above a TDX v4/v5 quote with its certification data (about 5 KiB to 8 KiB).
	MaxQuoteBytes = 64 << 10
	// MaxEventLogEntries bounds the event log; a Sealed stack's RTMR3 log has 10 entries, RTMR0-2 add a few hundred.
	MaxEventLogEntries = 4096
)

// releaseRequest is a parsed POST /v1/release body (INTERFACES.md section 9).
type releaseRequest struct {
	Nonce        [32]byte
	EphemeralPub [32]byte
	Quote        []byte
	EventLog     []byte // CJSON of the eventLog array
	Config       []byte // CJSON of the config object
	AppCompose   []byte
	ReleaseIDs   [][32]byte
	ImageID      [32]byte
}

var requestKeys = []string{"appCompose", "config", "ephemeralPub", "eventLog", "imageId", "nonce", "quote", "releaseIds"}

var eventKeys = []string{"digest", "event", "event_payload", "event_type", "imr", "version"}

// parseEnvelope parses the body as strict JSON (no duplicate or unknown keys, no floats, valid UTF-8).
func parseEnvelope(body []byte) (map[string]any, error) {
	v, err := cjson.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("body is not strict JSON: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("body must be a JSON object")
	}
	if err := onlyKeys(m, requestKeys, ""); err != nil {
		return nil, err
	}
	return m, nil
}

func onlyKeys(m map[string]any, allowed []string, where string) error {
	var extra []string
	for k := range m {
		if !slices.Contains(allowed, k) {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("unknown field %s%q", where, extra)
	}
	return nil
}

func requestNonce(m map[string]any) ([32]byte, error) {
	return hex32(m, "nonce")
}

// parseRequest validates every field except the nonce, which the caller already consumed.
func parseRequest(m map[string]any) (*releaseRequest, error) {
	r := &releaseRequest{}
	var err error
	if r.Nonce, err = hex32(m, "nonce"); err != nil {
		return nil, err
	}
	if r.EphemeralPub, err = hex32(m, "ephemeralPub"); err != nil {
		return nil, err
	}
	if r.ImageID, err = hex32(m, "imageId"); err != nil {
		return nil, err
	}
	qs, ok := m["quote"].(string)
	if !ok {
		return nil, errors.New("quote: missing or not a string")
	}
	if r.Quote, err = decodeHex(qs, "quote"); err != nil {
		return nil, err
	}
	if len(r.Quote) > MaxQuoteBytes {
		return nil, fmt.Errorf("quote: %d bytes, at most %d", len(r.Quote), MaxQuoteBytes)
	}
	evs, ok := m["eventLog"].([]any)
	if !ok {
		return nil, errors.New("eventLog: missing or not an array")
	}
	if len(evs) > MaxEventLogEntries {
		return nil, fmt.Errorf("eventLog: %d entries, at most %d", len(evs), MaxEventLogEntries)
	}
	for i, e := range evs {
		em, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("eventLog[%d]: not an object", i)
		}
		if err := onlyKeys(em, eventKeys, fmt.Sprintf("eventLog[%d].", i)); err != nil {
			return nil, err
		}
	}
	if r.EventLog, err = cjson.Encode(evs); err != nil {
		return nil, fmt.Errorf("eventLog: %v", err)
	}
	cfg, ok := m["config"].(map[string]any)
	if !ok {
		return nil, errors.New("config: missing or not an object")
	}
	if r.Config, err = cjson.Encode(cfg); err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	if len(r.Config) > composer.MaxConfigBytes {
		return nil, fmt.Errorf("config: %d bytes, at most %d", len(r.Config), composer.MaxConfigBytes)
	}
	ac, ok := m["appCompose"].(string)
	if !ok || ac == "" {
		return nil, errors.New("appCompose: missing or not a non-empty string")
	}
	if len(ac) > composer.MaxAppComposeBytes {
		return nil, fmt.Errorf("appCompose: %d bytes, at most %d", len(ac), composer.MaxAppComposeBytes)
	}
	r.AppCompose = []byte(ac)
	ids, ok := m["releaseIds"].([]any)
	if !ok || len(ids) == 0 {
		return nil, errors.New("releaseIds: missing or empty")
	}
	if len(ids) > composer.MaxConfigApps {
		return nil, fmt.Errorf("releaseIds: %d entries, at most %d", len(ids), composer.MaxConfigApps)
	}
	for i, v := range ids {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("releaseIds[%d]: not a string", i)
		}
		b, err := decodeHex(s, fmt.Sprintf("releaseIds[%d]", i))
		if err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("releaseIds[%d]: %d bytes, want 32", i, len(b))
		}
		r.ReleaseIDs = append(r.ReleaseIDs, [32]byte(b))
	}
	return r, nil
}

func hex32(m map[string]any, field string) ([32]byte, error) {
	var out [32]byte
	s, ok := m[field].(string)
	if !ok {
		return out, fmt.Errorf("%s: missing or not a string", field)
	}
	b, err := decodeHex(s, field)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%s: %d bytes, want 32", field, len(b))
	}
	return [32]byte(b), nil
}

func decodeHex(s, field string) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, "0x")
	if !ok {
		return nil, fmt.Errorf("%s: missing 0x prefix", field)
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex", field)
	}
	return b, nil
}

func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }
