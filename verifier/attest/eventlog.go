package attest

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sealed-dev/sealed/verifier/internal/strictjson"
)

// DstackRuntimeEventType is the event_type of dstack runtime (RTMR3) events.
const DstackRuntimeEventType = 0x08000001

// Fixed payloads of the Sealed stack's RTMR3 events (INTERFACES.md section 6).
const (
	KeyProviderPayload      = `{"name":"tpm","id":""}`
	StorageFSPayload        = "ext4"
	StorageEncryptedPayload = "1"
)

// NoGPUPolicyHash is sha256("{}"), the gpu-policy-hash dstack emits when the compose has no GPU policy.
var NoGPUPolicyHash = mustHex32("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")

// Event is one entry of a dstack event log as returned by GetQuote (JSON).
type Event struct {
	IMR          uint32 `json:"imr"`
	EventType    uint32 `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
	// Version is set by dstack for event log v2 entries. Only v1 (absent or 1) is accepted.
	Version *int `json:"version,omitempty"`
}

// RuntimeInfo is what the RTMR3 events of a Sealed stack attest to.
type RuntimeInfo struct {
	RTMR3            Measurement
	AppID            [20]byte
	ComposeHash      [32]byte
	InstanceID       [20]byte
	KeyProvider      string
	StorageFS        string
	StorageEncrypted bool
}

// RuntimeParams are the variable inputs of the expected RTMR3 sequence.
type RuntimeParams struct {
	AppID       [20]byte
	ComposeHash [32]byte
	InstanceID  [20]byte
}

// ParseEventLog parses a dstack event log JSON array.
func ParseEventLog(raw []byte) ([]Event, error) {
	var evs []Event
	if err := strictjson.Unmarshal(raw, &evs); err != nil {
		return nil, fmt.Errorf("%w: event log: %v", ErrRTMR3Replay, err)
	}
	return evs, nil
}

// EventDigestV1 is sha384(le32(0x08000001) || ":" || name || ":" || payload), the dstack v1 event digest.
func EventDigestV1(name string, payload []byte) Measurement {
	pre := make([]byte, 0, 6+len(name)+len(payload))
	pre = binary.LittleEndian.AppendUint32(pre, DstackRuntimeEventType)
	pre = append(pre, ':')
	pre = append(pre, name...)
	pre = append(pre, ':')
	pre = append(pre, payload...)
	return sha512.Sum384(pre)
}

// ExtendRTMR returns sha384(mr || digest).
func ExtendRTMR(mr, digest Measurement) Measurement {
	h := sha512.New384()
	h.Write(mr[:])
	h.Write(digest[:])
	var out Measurement
	copy(out[:], h.Sum(nil))
	return out
}

// ReplayRTMR3 replays the RTMR3 (imr 3) events from 48 zero bytes. Each event's digest field must equal the
// digest recomputed from its name and payload. Events of imr 0..2 are skipped (RTMR0-2 are pinned through the
// image's measurementsHash); any other imr is rejected.
func ReplayRTMR3(evs []Event) (Measurement, []Event, error) {
	var mr Measurement
	var rt []Event
	for i, e := range evs {
		switch {
		case e.IMR < 3:
			continue
		case e.IMR > 3:
			return mr, nil, fmt.Errorf("%w: event %d: unexpected imr %d", ErrRTMR3Replay, i, e.IMR)
		}
		if e.EventType != DstackRuntimeEventType {
			return mr, nil, fmt.Errorf("%w: event %d (%q): event_type 0x%x", ErrRTMR3Replay, i, e.Event, e.EventType)
		}
		if e.Version != nil && *e.Version != 1 {
			return mr, nil, fmt.Errorf("%w: event %d (%q): event log version %d not supported", ErrRTMR3Replay, i, e.Event, *e.Version)
		}
		payload, err := hex.DecodeString(e.EventPayload)
		if err != nil {
			return mr, nil, fmt.Errorf("%w: event %d (%q): payload: %v", ErrRTMR3Replay, i, e.Event, err)
		}
		d := EventDigestV1(e.Event, payload)
		claimed, err := hex.DecodeString(strings.TrimPrefix(e.Digest, "0x"))
		if err != nil || !bytes.Equal(claimed, d[:]) {
			return mr, nil, fmt.Errorf("%w: event %d (%q): digest does not match name and payload", ErrRTMR3Replay, i, e.Event)
		}
		mr = ExtendRTMR(mr, d)
		rt = append(rt, e)
	}
	return mr, rt, nil
}

type expectedEvent struct {
	name  string
	check func(p []byte, info *RuntimeInfo) error
}

func exactPayload(want string) func([]byte, *RuntimeInfo) error {
	return func(p []byte, _ *RuntimeInfo) error {
		if string(p) != want {
			return fmt.Errorf("payload %q, want %q", p, want)
		}
		return nil
	}
}

func sizedPayload(n int, dst func(*RuntimeInfo) []byte) func([]byte, *RuntimeInfo) error {
	return func(p []byte, info *RuntimeInfo) error {
		if len(p) != n {
			return fmt.Errorf("payload is %d bytes, want %d", len(p), n)
		}
		copy(dst(info), p)
		return nil
	}
}

// expectedSequence is the exact RTMR3 sequence of a Sealed stack on dstack v0.6.1 (no init scripts, no GPU,
// key_provider tpm, ext4, encrypted storage).
var expectedSequence = []expectedEvent{
	{"system-preparing", exactPayload("")},
	{"app-id", sizedPayload(20, func(i *RuntimeInfo) []byte { return i.AppID[:] })},
	{"compose-hash", sizedPayload(32, func(i *RuntimeInfo) []byte { return i.ComposeHash[:] })},
	{"gpu-policy-hash", exactPayload(string(NoGPUPolicyHash[:]))},
	{"instance-id", sizedPayload(20, func(i *RuntimeInfo) []byte { return i.InstanceID[:] })},
	{"boot-mr-done", exactPayload("")},
	{"key-provider", func(p []byte, i *RuntimeInfo) error {
		i.KeyProvider = string(p)
		return exactPayload(KeyProviderPayload)(p, i)
	}},
	{"storage-fs", func(p []byte, i *RuntimeInfo) error {
		i.StorageFS = string(p)
		return exactPayload(StorageFSPayload)(p, i)
	}},
	{"storage-encrypted", func(p []byte, i *RuntimeInfo) error {
		i.StorageEncrypted = string(p) == "1"
		return exactPayload(StorageEncryptedPayload)(p, i)
	}},
	{"system-ready", exactPayload("")},
}

// CheckRuntimeEvents replays RTMR3, requires it to equal quoteRTMR3 and requires exactly the expected event
// sequence: unknown, missing, extra or out-of-order events are rejected.
func CheckRuntimeEvents(evs []Event, quoteRTMR3 Measurement) (*RuntimeInfo, error) {
	mr, rt, err := ReplayRTMR3(evs)
	if err != nil {
		return nil, err
	}
	if mr != quoteRTMR3 {
		return nil, fmt.Errorf("%w: replayed RTMR3 %x does not match the quote's %x", ErrRTMR3Replay, mr, quoteRTMR3)
	}
	info := &RuntimeInfo{RTMR3: mr}
	for i, want := range expectedSequence {
		if i >= len(rt) {
			return nil, fmt.Errorf("%w: event %d: missing %q", ErrRTMR3Replay, i, want.name)
		}
		if rt[i].Event != want.name {
			return nil, fmt.Errorf("%w: event %d: got %q, want %q", ErrRTMR3Replay, i, rt[i].Event, want.name)
		}
		payload, _ := hex.DecodeString(rt[i].EventPayload) // validated by ReplayRTMR3
		if err := want.check(payload, info); err != nil {
			return nil, fmt.Errorf("%w: event %q: %v", ErrRTMR3Replay, want.name, err)
		}
	}
	if len(rt) > len(expectedSequence) {
		return nil, fmt.Errorf("%w: unexpected event %q after system-ready", ErrRTMR3Replay, rt[len(expectedSequence)].Event)
	}
	return info, nil
}

// ExpectedRuntimeEvents returns the RTMR3 event log a Sealed stack produces, in dstack's JSON shape. The dev
// simulator emits exactly this; tests use it to build fixtures.
func ExpectedRuntimeEvents(p RuntimeParams) []Event {
	payloads := map[string][]byte{
		"app-id":            p.AppID[:],
		"compose-hash":      p.ComposeHash[:],
		"gpu-policy-hash":   NoGPUPolicyHash[:],
		"instance-id":       p.InstanceID[:],
		"key-provider":      []byte(KeyProviderPayload),
		"storage-fs":        []byte(StorageFSPayload),
		"storage-encrypted": []byte(StorageEncryptedPayload),
	}
	evs := make([]Event, 0, len(expectedSequence))
	for _, want := range expectedSequence {
		payload := payloads[want.name]
		d := EventDigestV1(want.name, payload)
		evs = append(evs, Event{
			IMR:          3,
			EventType:    DstackRuntimeEventType,
			Digest:       hex.EncodeToString(d[:]),
			Event:        want.name,
			EventPayload: hex.EncodeToString(payload),
		})
	}
	return evs
}

// ReplayAll folds every event's digest without sequence checks. It is used to compute the RTMR3 a simulator
// sets for a given event log.
func ReplayAll(evs []Event) (Measurement, error) {
	mr, _, err := ReplayRTMR3(evs)
	return mr, err
}

func mustHex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("bad constant " + s)
	}
	copy(out[:], b)
	return out
}
