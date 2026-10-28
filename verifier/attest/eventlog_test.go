package attest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type rtmrVectors struct {
	AppIDDeadbeefDigest string `json:"appIdDeadbeefDigest"`
	ComposeBytes        string `json:"composeBytes"`
	ComposeHash         string `json:"composeHash"`
	Dstack              struct {
		Events          []Event `json:"events"`
		RTMR3           string  `json:"rtmr3"`
		RTMR3BootMrDone string  `json:"rtmr3BootMrDone"`
	} `json:"dstack"`
	Sealed struct {
		Events []Event `json:"events"`
		RTMR3  string  `json:"rtmr3"`
	} `json:"sealed"`
	ReportData map[string]any `json:"reportData"`
}

func loadVectors(t *testing.T) rtmrVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rtmr3", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v rtmrVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustMeasurement(t *testing.T, s string) Measurement {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 48 {
		t.Fatalf("bad measurement %q", s)
	}
	var m Measurement
	copy(m[:], b)
	return m
}

func sealedParams(t *testing.T, v rtmrVectors) RuntimeParams {
	var p RuntimeParams
	for i := range p.AppID {
		p.AppID[i] = 0x11
		p.InstanceID[i] = 0x33
	}
	ch, _ := hex.DecodeString(v.ComposeHash)
	copy(p.ComposeHash[:], ch)
	return p
}

// TestDstackGoldenVectors checks the digest and fold against docs/notes/dstack.md section 6.3.
func TestDstackGoldenVectors(t *testing.T) {
	v := loadVectors(t)
	d := EventDigestV1("app-id", []byte{0xde, 0xad, 0xbe, 0xef})
	if hex.EncodeToString(d[:]) != v.AppIDDeadbeefDigest ||
		v.AppIDDeadbeefDigest != "67b4be4efed0893cfa2bb1d35dca209ad8348b4c97f980807bcde8b9a0f26398dd0923d6eccb5aa2096d98046da8740f" {
		t.Fatalf("app-id digest %x", d)
	}
	if v.Dstack.RTMR3 != "30498094c86fca91569d7ea7dc79fcfd7dfbf7ac699a1fde8b673f659e1f0fcc08ee73fdccd5eb000694689b212822d1" {
		t.Fatal("vectors.json drifted from docs/notes/dstack.md 6.3")
	}
	mr, err := ReplayAll(v.Dstack.Events)
	if err != nil {
		t.Fatal(err)
	}
	if mr != mustMeasurement(t, v.Dstack.RTMR3) {
		t.Fatalf("RTMR3 %x", mr)
	}
	boot, err := ReplayAll(v.Dstack.Events[:6])
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(boot[:]) != "5087565e0705ebbd36500f414ef35cff648b28d342eb1b2ac370909e46e866c19b817bec801d0877960febdb4283b00d" {
		t.Fatalf("boot-mr-done RTMR3 %x", boot)
	}
	// The dstack note's sequence uses key provider "none"; Sealed requires "tpm".
	if _, err := CheckRuntimeEvents(v.Dstack.Events, mr); err == nil || !strings.Contains(err.Error(), "key-provider") {
		t.Fatalf("key provider none accepted: %v", err)
	}
}

func TestSealedSequence(t *testing.T) {
	v := loadVectors(t)
	p := sealedParams(t, v)
	evs := ExpectedRuntimeEvents(p)
	if !reflect.DeepEqual(evs, v.Sealed.Events) {
		got, _ := json.Marshal(evs)
		t.Fatalf("ExpectedRuntimeEvents differs from the Python vectors:\n%s", got)
	}
	info, err := CheckRuntimeEvents(evs, mustMeasurement(t, v.Sealed.RTMR3))
	if err != nil {
		t.Fatal(err)
	}
	if info.ComposeHash != p.ComposeHash || info.AppID != p.AppID || info.InstanceID != p.InstanceID {
		t.Fatal("extracted fields")
	}
	if info.KeyProvider != KeyProviderPayload || info.StorageFS != "ext4" || !info.StorageEncrypted {
		t.Fatalf("extracted %+v", info)
	}
	// RTMR0-2 entries (firmware CCEL) may be interleaved and are not part of the RTMR3 replay.
	withBoot := append([]Event{{IMR: 0, EventType: 0x80000001, Digest: "aa", Event: ""}, {IMR: 2, EventType: 13}}, evs...)
	if _, err := CheckRuntimeEvents(withBoot, mustMeasurement(t, v.Sealed.RTMR3)); err != nil {
		t.Fatal(err)
	}
}

func cloneEvents(evs []Event) []Event { return append([]Event(nil), evs...) }

func setPayload(e *Event, payload []byte) {
	d := EventDigestV1(e.Event, payload)
	e.EventPayload = hex.EncodeToString(payload)
	e.Digest = hex.EncodeToString(d[:])
}

func rename(e *Event, name string) {
	p, _ := hex.DecodeString(e.EventPayload)
	e.Event = name
	setPayload(e, p)
}

// TestSequenceTampering mutates the expected log, recomputes digests and RTMR3 so the replay itself succeeds,
// and requires the sequence check to reject each case.
func TestSequenceTampering(t *testing.T) {
	v := loadVectors(t)
	base := ExpectedRuntimeEvents(sealedParams(t, v))
	cases := map[string]func([]Event) []Event{
		"unknown event appended": func(e []Event) []Event {
			x := Event{IMR: 3, EventType: DstackRuntimeEventType, Event: "app-data"}
			setPayload(&x, []byte("hi"))
			return append(e, x)
		},
		"init-script-hash inserted": func(e []Event) []Event {
			x := Event{IMR: 3, EventType: DstackRuntimeEventType, Event: "init-script-hash"}
			setPayload(&x, make([]byte, 32))
			return append(e[:3:3], append([]Event{x}, e[3:]...)...)
		},
		"swapped order":        func(e []Event) []Event { e[1], e[2] = e[2], e[1]; return e },
		"missing system-ready": func(e []Event) []Event { return e[:9] },
		"duplicate compose-hash": func(e []Event) []Event {
			return append(e[:3:3], append([]Event{e[2]}, e[3:]...)...)
		},
		"renamed event":           func(e []Event) []Event { rename(&e[0], "system-preparing2"); return e },
		"key provider none":       func(e []Event) []Event { setPayload(&e[6], []byte(`{"name":"none","id":""}`)); return e },
		"key provider kms":        func(e []Event) []Event { setPayload(&e[6], []byte(`{"name":"kms","id":"ab"}`)); return e },
		"storage zfs":             func(e []Event) []Event { setPayload(&e[7], []byte("zfs")); return e },
		"storage not encrypted":   func(e []Event) []Event { setPayload(&e[8], []byte("0")); return e },
		"gpu policy set":          func(e []Event) []Event { setPayload(&e[3], make([]byte, 32)); return e },
		"short app-id":            func(e []Event) []Event { setPayload(&e[1], make([]byte, 19)); return e },
		"empty instance-id":       func(e []Event) []Event { setPayload(&e[4], nil); return e },
		"long compose-hash":       func(e []Event) []Event { setPayload(&e[2], make([]byte, 33)); return e },
		"payload on boot-mr-done": func(e []Event) []Event { setPayload(&e[5], []byte{1}); return e },
		"empty log":               func(e []Event) []Event { return nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			evs := mutate(cloneEvents(base))
			mr, err := ReplayAll(evs)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CheckRuntimeEvents(evs, mr); !errors.Is(err, ErrRTMR3Replay) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
}

func TestReplayTampering(t *testing.T) {
	v := loadVectors(t)
	base := ExpectedRuntimeEvents(sealedParams(t, v))
	good := mustMeasurement(t, v.Sealed.RTMR3)
	cases := map[string]func([]Event) []Event{
		"payload changed, digest kept": func(e []Event) []Event { e[2].EventPayload = strings.Repeat("00", 32); return e },
		"digest changed":               func(e []Event) []Event { e[0].Digest = strings.Repeat("00", 48); return e },
		"digest missing":               func(e []Event) []Event { e[0].Digest = ""; return e },
		"wrong event_type":             func(e []Event) []Event { e[3].EventType = 1; return e },
		"imr 4":                        func(e []Event) []Event { e[0].IMR = 4; return e },
		"v2 event":                     func(e []Event) []Event { two := 2; e[0].Version = &two; return e },
		"payload not hex":              func(e []Event) []Event { e[1].EventPayload = "zz"; return e },
		"event moved to imr 2":         func(e []Event) []Event { e[9].IMR = 2; return e },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CheckRuntimeEvents(mutate(cloneEvents(base)), good); !errors.Is(err, ErrRTMR3Replay) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
	t.Run("quote RTMR3 differs", func(t *testing.T) {
		bad := good
		bad[47] ^= 1
		if _, err := CheckRuntimeEvents(cloneEvents(base), bad); !errors.Is(err, ErrRTMR3Replay) {
			t.Fatal("accepted")
		}
	})
}

func TestParseEventLog(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	raw := `[{"imr":3,"event_type":134217729,"digest":"` + digest + `","event":"system-preparing","event_payload":"","extra":1}]`
	evs, err := ParseEventLog([]byte(raw))
	if err != nil || len(evs) != 1 || evs[0].Event != "system-preparing" {
		t.Fatalf("%v %+v", err, evs)
	}
	if _, err := ParseEventLog([]byte(`{"not":"an array"}`)); !errors.Is(err, ErrRTMR3Replay) {
		t.Fatal("object accepted")
	}
}

// V-4: digests and payloads only in dstack's spelling, so the same events cannot be re-spelled into another
// eventLogHash for the same quote. Applies to every imr (entries of imr 0 to 2 are not replayed).
func TestParseEventLogRequiresDstackHex(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	entry := func(imr int, digest, payload string) string {
		return fmt.Sprintf(`[{"imr":%d,"event_type":10,"digest":%q,"event":"acpi-loader","event_payload":%q}]`, imr, digest, payload)
	}
	if _, err := ParseEventLog([]byte(entry(0, digest, "0a0b"))); err != nil {
		t.Fatalf("dstack spelling refused: %v", err)
	}
	for name, raw := range map[string]string{
		"0x digest":           entry(3, "0x"+digest, ""),
		"uppercase digest":    entry(0, strings.ToUpper(digest), ""),
		"short digest":        entry(1, digest[:94], ""),
		"long digest":         entry(2, digest+"ab", ""),
		"sha256-sized digest": entry(3, strings.Repeat("ab", 32), ""),
		"not hex":             entry(3, strings.Repeat("zz", 48), ""),
		"0x payload":          entry(3, digest, "0x0a"),
		"uppercase payload":   entry(0, digest, "0A"),
		"odd payload":         entry(3, digest, "abc"),
	} {
		if _, err := ParseEventLog([]byte(raw)); !errors.Is(err, ErrRTMR3Replay) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	// The real GCP capture is in that spelling.
	raw, err := os.ReadFile(filepath.Join("testdata", "gcp", "eventlog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if evs, err := ParseEventLog(raw); err != nil || len(evs) != 45 {
		t.Fatalf("GCP event log: %d events, %v", len(evs), err)
	}
}
