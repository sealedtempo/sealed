package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

// gcpDir holds the real capture of the runtime spike: dstack 0.6.1 (upstream image, D-016: never register it) on
// a Google Cloud c3-standard-4 TDX VM, two boots of the same VM, two GetQuote calls per boot. See its README.md.
var gcpDir = filepath.Join("testdata", "gcp")

// gcpGolden describes testdata/gcp/expected.json.
type gcpGolden struct {
	// Captures are the GetQuote responses in captures/<name>.json. Each has a nonce in captures/<boot>-nonce<k>.txt
	// and report_data = sha256(ReportDataTag || nonce) || 32 zero bytes.
	Captures []struct {
		Name       string    `json:"name"`
		CapturedAt time.Time `json:"capturedAt"`
	} `json:"captures"`
	ReportDataTag string `json:"reportDataTag"`
	QuoteVersion  uint32 `json:"quoteVersion"`
	// SignedQuoteLength is header + TD body + signature length + signature data; GetQuoteLength is what dstack
	// returned (the signed quote followed by zero padding).
	SignedQuoteLength int `json:"signedQuoteLength"`
	GetQuoteLength    int `json:"getQuoteLength"`
	// The TCB result against the collateral in pcs/, at its recording time (pcs/recorded.json).
	FMSPC             string   `json:"fmspc"`
	TCBStatus         string   `json:"tcbStatus"`
	PlatformTCBStatus string   `json:"platformTcbStatus"`
	ModuleTCBStatus   string   `json:"moduleTcbStatus"`
	QETCBStatus       string   `json:"qeTcbStatus"`
	AdvisoryIDs       []string `json:"advisoryIds"`
	// QuoteHash (sha256 of the signed quote, INTERFACES 2) and EventLogHash (sha256(CJSON(event log))) are those
	// of the top-level quote.dat and eventlog.json; the TypeScript agent tests assert the same values.
	QuoteHash        string `json:"quoteHash"`
	EventLogHash     string `json:"eventLogHash"`
	MeasurementsHash string `json:"measurementsHash"`
	RTMR3            string `json:"rtmr3"`
	// ComposeHash is sha256(app-compose.json), the stackHash.
	ComposeHash string `json:"composeHash"`
	AppID       string `json:"appId"`
	InstanceID  string `json:"instanceId"`
	// TDAttributes and XFAM (hex, as in the quote) are chosen by the host and not measured: the capture records
	// what GCP sets so a per-image pin can be added to PlatformRegistry or the policy.
	TDAttributes string `json:"tdAttributes"`
	XFAM         string `json:"xfam"`
}

// getQuoteResponse is the guest agent's POST /GetQuote answer, as captured.
type getQuoteResponse struct {
	Quote      string `json:"quote"`
	EventLog   string `json:"event_log"`
	ReportData string `json:"report_data"`
	VMConfig   string `json:"vm_config"`
}

func readGCPGolden(t *testing.T) gcpGolden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(gcpDir, "expected.json"))
	if os.IsNotExist(err) {
		t.Skip("no real GCP quote captured (testdata/gcp/expected.json missing)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var exp gcpGolden
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	if len(exp.Captures) == 0 {
		t.Fatal("expected.json lists no captures")
	}
	return exp
}

func readGCPFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(gcpDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readHexFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimSpace(string(readGCPFile(t, rel))))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return b
}

// readCapture returns the GetQuote response of capture name ("boot1-getquote2") and its nonce.
func readCapture(t *testing.T, name string) (getQuoteResponse, []byte) {
	t.Helper()
	var r getQuoteResponse
	if err := json.Unmarshal(readGCPFile(t, filepath.Join("captures", name+".json")), &r); err != nil {
		t.Fatal(err)
	}
	boot, k, ok := strings.Cut(name, "-getquote")
	if !ok {
		t.Fatalf("capture name %q", name)
	}
	return r, readHexFile(t, filepath.Join("captures", boot+"-nonce"+k+".txt"))
}

// repoTCBPolicy is the tcb_policy of config/defaults.yaml: what sealed-verifierd loads with -defaults, and equal to
// DefaultTCBPolicy (TestTCBPolicyFromRepoDefaults).
func repoTCBPolicy(t *testing.T) TCBPolicy {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := TCBPolicyFromDefaults(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// replayCCEL folds the digests of the firmware (CCEL) entries of imr from 48 zero bytes. The verifier does not do
// this (RTMR0-2 are pinned as a whole through measurementsHash); the golden test uses it to check the fixture.
func replayCCEL(t *testing.T, evs []Event, imr uint32) (Measurement, int) {
	t.Helper()
	var mr Measurement
	n := 0
	for _, e := range evs {
		if e.IMR != imr {
			continue
		}
		var d Measurement
		b, err := hex.DecodeString(e.Digest)
		if err != nil || len(b) != MeasurementSize {
			t.Fatalf("imr %d digest %q", imr, e.Digest)
		}
		copy(d[:], b)
		mr = ExtendRTMR(mr, d)
		n++
	}
	return mr, n
}

func hexEq(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s = %x, want %s", what, got, want)
	}
}

// TestRealGCPGolden verifies every real quote and event log of the runtime spike the way the verifier and the key
// broker do, offline against the recorded Intel collateral, with the TCB policy of config/defaults.yaml.
//
// To refresh after a new capture: put the GetQuote responses in captures/, record collateral with
// go run ./verifier/internal/tools/pcsrecord -out verifier/attest/testdata/gcp/pcs verifier/attest/testdata/gcp/quote.dat
// and update expected.json.
func TestRealGCPGolden(t *testing.T) {
	exp := readGCPGolden(t)
	ctx := context.Background()
	pcsDir := filepath.Join(gcpDir, "pcs")
	verifiedAt := recordedTimeDir(t, pcsDir)
	policy := repoTCBPolicy(t)
	v := recordedVerifierDir(t, pcsDir, policy, 0)

	appCompose := readGCPFile(t, "app-compose.json")
	stackHash := sha256.Sum256(appCompose)
	hexEq(t, "sha256(app-compose.json)", stackHash[:], exp.ComposeHash)

	byName := map[string]*Quote{}
	for _, c := range exp.Captures {
		t.Run(c.Name, func(t *testing.T) {
			if c.CapturedAt.IsZero() || c.CapturedAt.After(verifiedAt) {
				t.Fatalf("capturedAt %v must be set and before the collateral recording time %v", c.CapturedAt, verifiedAt)
			}
			gq, nonce := readCapture(t, c.Name)
			padded, err := hex.DecodeString(gq.Quote)
			if err != nil {
				t.Fatal(err)
			}

			// Canonical length: GetQuote returns the signed quote inside a zero-filled buffer. Neither ParseQuote nor
			// VerifyQuote accepts it (the padding is signed by nothing, so it would give one quote many quoteHash
			// values); TrimQuote cuts exactly the zeros and the signed length follows the v4 layout.
			if len(padded) != exp.GetQuoteLength {
				t.Fatalf("GetQuote returned %d bytes, want %d", len(padded), exp.GetQuoteLength)
			}
			if _, err := ParseQuote(padded, ParseOptions{}); !errors.Is(err, ErrQuoteInvalid) || !strings.Contains(err.Error(), "zero padding") {
				t.Fatalf("ParseQuote of the padded GetQuote bytes: %v", err)
			}
			if _, err := v.VerifyQuote(ctx, padded); !errors.Is(err, ErrQuoteInvalid) {
				t.Fatalf("VerifyQuote of the padded GetQuote bytes: %v", err)
			}
			signed, err := TrimQuote(padded)
			if err != nil {
				t.Fatal(err)
			}
			const v4Fixed = 48 + 584 + 4 // header, TD 1.0 body, signature data length
			if len(signed) != exp.SignedQuoteLength || len(signed) != v4Fixed+int(binary.LittleEndian.Uint32(signed[v4Fixed-4:v4Fixed])) {
				t.Fatalf("signed quote is %d bytes, want %d = %d + signature data length", len(signed), exp.SignedQuoteLength, v4Fixed)
			}
			if !bytes.Equal(padded[:len(signed)], signed) || !allZero(padded[len(signed):]) {
				t.Fatal("TrimQuote did not cut exactly the trailing zeros")
			}
			if again, err := TrimQuote(signed); err != nil || !bytes.Equal(again, signed) {
				t.Fatalf("TrimQuote is not idempotent: %v", err)
			}

			// Signature, PCK chain, QE report, collateral signatures, expiry and CRLs, then the configured policy.
			res, err := v.VerifyQuote(ctx, signed)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("verified at %s with %v: TDX TCB %s (platform %s, module %s), QE %s, FMSPC %s, tcbDate %s, module tcbDate %s, advisories %v",
				verifiedAt.UTC().Format(time.RFC3339), policy.AllowedStatuses, res.TCBStatus, res.PlatformTCBStatus, res.ModuleTCBStatus,
				res.QETCBStatus, res.FMSPC, res.TCBDate, res.ModuleTCBDate, res.AdvisoryIDs)
			q := res.Quote
			if res.Simulated || q.Version != exp.QuoteVersion || res.FMSPC != exp.FMSPC || res.TCBStatus != exp.TCBStatus ||
				res.PlatformTCBStatus != exp.PlatformTCBStatus || res.ModuleTCBStatus != exp.ModuleTCBStatus || res.QETCBStatus != exp.QETCBStatus {
				t.Errorf("simulated %v, v%d, FMSPC %s, TCB %s/%s/%s, QE %s; want v%d, %s, %s/%s/%s, %s", res.Simulated, q.Version, res.FMSPC,
					res.TCBStatus, res.PlatformTCBStatus, res.ModuleTCBStatus, res.QETCBStatus, exp.QuoteVersion, exp.FMSPC,
					exp.TCBStatus, exp.PlatformTCBStatus, exp.ModuleTCBStatus, exp.QETCBStatus)
			}
			if !slices.Equal(res.AdvisoryIDs, exp.AdvisoryIDs) && len(res.AdvisoryIDs)+len(exp.AdvisoryIDs) > 0 {
				t.Errorf("advisories %v, want %v", res.AdvisoryIDs, exp.AdvisoryIDs)
			}

			// report_data is the INTERFACES 3 shape with the spike's tag, over this capture's nonce.
			want := tagged(exp.ReportDataTag, nonce)
			if q.ReportData != want {
				t.Errorf("report_data %x, want sha256(%q || nonce) || zeros = %x", q.ReportData, exp.ReportDataTag, want)
			}
			hexEq(t, "GetQuote report_data", want[:], gq.ReportData)

			// Host-chosen attributes: the production rule passes on what GCP sets.
			if err := q.CheckProductionAttributes(); err != nil {
				t.Error(err)
			}
			if q.Debug() || q.Migratable() {
				t.Errorf("debug %v migratable %v", q.Debug(), q.Migratable())
			}
			hexEq(t, "td_attributes", q.TDAttributes[:], exp.TDAttributes)
			hexEq(t, "xfam", q.XFAM[:], exp.XFAM)

			mh := q.MeasurementsHash()
			hexEq(t, "measurementsHash", mh[:], exp.MeasurementsHash)

			// RTMR3: replay, the exact INTERFACES 6 sequence (key provider tpm), and the compose hash.
			evs, err := ParseEventLog([]byte(gq.EventLog))
			if err != nil {
				t.Fatal(err)
			}
			info, err := CheckRuntimeEvents(evs, q.RTMR[3])
			if err != nil {
				t.Fatal(err)
			}
			if info.ComposeHash != stackHash {
				t.Errorf("compose-hash event %x, want sha256(app-compose.json) %x", info.ComposeHash, stackHash)
			}
			hexEq(t, "rtmr3", info.RTMR3[:], exp.RTMR3)
			hexEq(t, "app-id", info.AppID[:], exp.AppID)
			hexEq(t, "instance-id", info.InstanceID[:], exp.InstanceID)
			if !bytes.Equal(info.AppID[:], stackHash[:20]) {
				t.Errorf("app-id %x is not the compose hash prefix", info.AppID)
			}
			if info.KeyProvider != KeyProviderPayload || info.StorageFS != StorageFSPayload || !info.StorageEncrypted {
				t.Errorf("runtime %+v", info)
			}

			// The firmware entries of the same log replay to RTMR0-2 (fixture check, see replayCCEL).
			for imr := uint32(0); imr < 3; imr++ {
				if mr, n := replayCCEL(t, evs, imr); mr != q.RTMR[imr] || n == 0 {
					t.Errorf("rtmr%d: CCEL replay of %d entries %x, quote %x", imr, n, mr, q.RTMR[imr])
				}
			}
			byName[c.Name] = q
		})
	}
	if t.Failed() || len(byName) != len(exp.Captures) {
		return
	}

	// Across the two GetQuote calls and the reboot only REPORTDATA (and the signature) change.
	first := byName[exp.Captures[0].Name]
	seen := map[ReportData]string{}
	for _, c := range exp.Captures {
		q := byName[c.Name]
		if q.MRTD != first.MRTD || q.RTMR != first.RTMR || q.TDAttributes != first.TDAttributes || q.XFAM != first.XFAM || q.TeeTcbSvn != first.TeeTcbSvn {
			t.Errorf("%s: measurements or attributes differ from %s", c.Name, exp.Captures[0].Name)
		}
		if prev, dup := seen[q.ReportData]; dup {
			t.Errorf("%s and %s have the same report_data", prev, c.Name)
		}
		seen[q.ReportData] = c.Name
	}

	// The top-level files are boot 1's first capture: quote.dat is its trimmed quote, quote-raw.hex its GetQuote
	// bytes, eventlog.json its event_log, report_data.txt and nonce.txt its inputs.
	gq, nonce := readCapture(t, exp.Captures[0].Name)
	if string(readGCPFile(t, "eventlog.json")) != gq.EventLog || !bytes.Equal(readHexFile(t, "nonce.txt"), nonce) ||
		strings.TrimSpace(string(readGCPFile(t, "report_data.txt"))) != gq.ReportData ||
		strings.TrimSpace(string(readGCPFile(t, "quote-raw.hex"))) != gq.Quote {
		t.Error("top-level fixture files are not boot1-getquote1")
	}
	if !bytes.Equal(readGCPFile(t, "quote.dat"), first.Raw) {
		t.Error("quote.dat is not the trimmed boot1-getquote1 quote")
	}
	qh := sha256.Sum256(first.Raw)
	hexEq(t, "quoteHash", qh[:], exp.QuoteHash)
	canon, err := cjson.Canonicalize([]byte(gq.EventLog))
	if err != nil {
		t.Fatal(err)
	}
	elh := sha256.Sum256(canon)
	hexEq(t, "eventLogHash", elh[:], exp.EventLogHash)

	// GET /Info: tcb_info carries the same registers and the exact app-compose.json bytes. sealed-agent reads
	// app_compose from here, so stackHash = sha256(tcb_info.app_compose).
	var infoResp struct {
		TCBInfo     string `json:"tcb_info"`
		ComposeHash string `json:"compose_hash"`
		AppID       string `json:"app_id"`
		InstanceID  string `json:"instance_id"`
	}
	if err := json.Unmarshal(readGCPFile(t, "info.json"), &infoResp); err != nil {
		t.Fatal(err)
	}
	var tcb struct {
		MRTD, RTMR0, RTMR1, RTMR2, RTMR3 string
		AppCompose                       string `json:"app_compose"`
		ComposeHash                      string `json:"compose_hash"`
	}
	if err := json.Unmarshal([]byte(infoResp.TCBInfo), &tcb); err != nil {
		t.Fatal(err)
	}
	hexEq(t, "tcb_info.mrtd", first.MRTD[:], tcb.MRTD)
	for i, r := range []string{tcb.RTMR0, tcb.RTMR1, tcb.RTMR2, tcb.RTMR3} {
		hexEq(t, "tcb_info.rtmr"+string(rune('0'+i)), first.RTMR[i][:], r)
	}
	if tcb.AppCompose != string(appCompose) || tcb.ComposeHash != exp.ComposeHash || infoResp.ComposeHash != exp.ComposeHash ||
		infoResp.AppID != exp.AppID || infoResp.InstanceID != exp.InstanceID {
		t.Error("/Info app_compose, compose_hash, app_id or instance_id differ from the quote's")
	}
}

// TestRealGCPGoldenRejects checks that the verifier's failure paths hold on the real quote, not only on fixtures:
// modified bytes, non-zero padding, a stricter policy, expired collateral and edited RTMR3 events.
func TestRealGCPGoldenRejects(t *testing.T) {
	readGCPGolden(t)
	ctx := context.Background()
	pcsDir := filepath.Join(gcpDir, "pcs")
	v := recordedVerifierDir(t, pcsDir, repoTCBPolicy(t), 0)
	signed := readGCPFile(t, "quote.dat")
	if _, err := v.VerifyQuote(ctx, signed); err != nil {
		t.Fatal(err)
	}

	t.Run("non-zero padding", func(t *testing.T) {
		padded := readHexFile(t, "quote-raw.hex")
		padded[len(padded)-1] = 1
		if _, err := TrimQuote(padded); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("TrimQuote cut non-zero bytes: %v", err)
		}
		if _, err := ParseQuote(padded, ParseOptions{}); !errors.Is(err, ErrQuoteInvalid) || !strings.Contains(err.Error(), "non-zero") {
			t.Fatalf("ParseQuote: %v", err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, err := ParseQuote(signed[:len(signed)-1], ParseOptions{}); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("truncated quote parsed: %v", err)
		}
	})
	t.Run("report_data changed", func(t *testing.T) {
		raw := bytes.Clone(signed)
		raw[48+520] ^= 1 // header + offset of REPORTDATA in the TD 1.0 body
		q, err := ParseQuote(raw, ParseOptions{})
		if err != nil || q.ReportData[0] == signed[48+520] {
			t.Fatalf("offset check: %v", err)
		}
		if _, err := v.VerifyQuote(ctx, raw); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("modified report_data verified: %v", err)
		}
	})
	t.Run("debug attribute set", func(t *testing.T) {
		raw := bytes.Clone(signed)
		raw[v4TDAttributesOffset] |= 1
		q, err := ParseQuote(raw, ParseOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := q.CheckProductionAttributes(); !errors.Is(err, ErrTDAttributes) {
			t.Fatalf("DEBUG accepted by the production rule: %v", err)
		}
		if _, err := v.VerifyQuote(ctx, raw); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("modified td_attributes verified: %v", err)
		}
	})
	t.Run("policy without UpToDate", func(t *testing.T) {
		strict := recordedVerifierDir(t, pcsDir, TCBPolicy{AllowedStatuses: []string{"SWHardeningNeeded"}}, 0)
		if _, err := strict.VerifyQuote(ctx, signed); !errors.Is(err, ErrTCBStatus) {
			t.Fatalf("policy not applied: %v", err)
		}
	})
	t.Run("collateral expired", func(t *testing.T) {
		// The recorded TCB info has nextUpdate 30 days after issue.
		late := recordedVerifierDir(t, pcsDir, repoTCBPolicy(t), 31*24*time.Hour)
		if _, err := late.VerifyQuote(ctx, signed); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("expired collateral accepted: %v", err)
		}
	})
	t.Run("no collateral", func(t *testing.T) {
		g, _ := NewCachingGetter(CacheOptions{Inner: offlineGetter{}})
		empty, _ := NewVerifier(VerifierOptions{Getter: g, Now: func() time.Time { return recordedTimeDir(t, pcsDir) }})
		if _, err := empty.VerifyQuote(ctx, signed); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("verified without collateral: %v", err)
		}
	})

	q, err := ParseQuote(signed, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := ParseEventLog(readGCPFile(t, "eventlog.json"))
	if err != nil {
		t.Fatal(err)
	}
	rtStart := slices.IndexFunc(evs, func(e Event) bool { return e.IMR == 3 })
	for name, edit := range map[string]func([]Event) []Event{
		"compose-hash payload": func(e []Event) []Event {
			e[rtStart+2].EventPayload = strings.Repeat("00", 32)
			return e
		},
		"compose-hash digest and payload": func(e []Event) []Event {
			p := bytes.Repeat([]byte{0xaa}, 32)
			d := EventDigestV1("compose-hash", p)
			e[rtStart+2].EventPayload, e[rtStart+2].Digest = hex.EncodeToString(p), hex.EncodeToString(d[:])
			return e
		},
		"key-provider dropped": func(e []Event) []Event { return slices.Delete(e, rtStart+6, rtStart+7) },
		"extra event":          func(e []Event) []Event { return append(e, ExpectedRuntimeEvents(RuntimeParams{})[0]) },
		"runtime events only":  func(e []Event) []Event { return e[rtStart:] }, // fine: RTMR0-2 entries are not replayed
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CheckRuntimeEvents(edit(slices.Clone(evs)), q.RTMR[3])
			if name == "runtime events only" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrRTMR3Replay) {
				t.Fatalf("edited event log accepted: %v", err)
			}
		})
	}
}
