package attest

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Fuzz targets for the quote parser, offline quote verification and the
// dstack event log (RTMR3) replay. Every input here comes from the TD (or
// whoever claims to be one): the agent's evidence, a key release request.

// fuzzVerifier verifies offline against the recorded collateral in dir at its
// recording time (the fuzz twin of recordedVerifierDir).
func fuzzVerifier(tb testing.TB, dir string, policy TCBPolicy) *Verifier {
	raw, err := os.ReadFile(filepath.Join(dir, "recorded.json"))
	if err != nil {
		tb.Fatal(err)
	}
	var meta struct {
		RecordedAt int64 `json:"recordedAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		tb.Fatal(err)
	}
	at := time.Unix(meta.RecordedAt, 0)
	getter, err := NewCachingGetter(CacheOptions{Dir: dir, TTL: 100 * 365 * 24 * time.Hour, Inner: offlineGetter{}, Now: func() time.Time { return at }})
	if err != nil {
		tb.Fatal(err)
	}
	v, err := NewVerifier(VerifierOptions{Getter: getter, TCBPolicy: policy, Now: func() time.Time { return at }})
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func fuzzPolicy(tb testing.TB) TCBPolicy {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		tb.Fatal(err)
	}
	p, err := TCBPolicyFromDefaults(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

// fuzzQuoteFiles are every real quote in testdata, as GetQuote returned them
// (padded) and trimmed.
func fuzzQuoteFiles(tb testing.TB) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		out = append(out, b)
		if t, err := TrimQuote(b); err == nil && len(t) != len(b) {
			out = append(out, t)
		}
	}
	paths, _ := filepath.Glob(filepath.Join("testdata", "quotes", "*.dat"))
	more, _ := filepath.Glob(filepath.Join("testdata", "gcp", "*", "quote.dat"))
	paths = append(append(paths, filepath.Join("testdata", "gcp", "quote.dat")), more...)
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			add(b)
		}
	}
	caps, _ := filepath.Glob(filepath.Join("testdata", "gcp", "captures", "*-getquote*.json"))
	for _, p := range caps {
		var r struct {
			Quote string `json:"quote"`
		}
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &r) == nil {
			if q, err := hex.DecodeString(r.Quote); err == nil {
				add(q)
			}
		}
	}
	if len(out) < 4 {
		tb.Fatalf("only %d quote fixtures", len(out))
	}
	return out
}

// FuzzParseQuote: ParseQuote never panics and every error wraps
// ErrQuoteInvalid; an accepted quote keeps exactly the input bytes, has no
// unsigned trailing bytes, parses again to the same fields; a simulated quote
// is refused unless allowed and is the unique canonical encoding of its
// fields.
func FuzzParseQuote(f *testing.F) {
	for _, q := range fuzzQuoteFiles(f) {
		f.Add(q)
	}
	f.Add(NewSimQuote(SimQuoteParams{}))
	f.Add(NewSimQuote(SimQuoteParams{Debug: true, RTMR3: fill(0x77), ReportData: ReportData{1, 2, 3}}))
	f.Fuzz(func(t *testing.T, raw []byte) {
		strict, serr := ParseQuote(raw, ParseOptions{})
		q, err := ParseQuote(raw, ParseOptions{AllowSimulated: true})
		for _, e := range []error{serr, err} {
			if e != nil && !errors.Is(e, ErrQuoteInvalid) {
				t.Fatalf("error does not wrap ErrQuoteInvalid: %v", e)
			}
		}
		if IsSimulatedQuote(raw) && serr == nil {
			t.Fatal("simulated quote accepted without AllowSimulated")
		}
		if !IsSimulatedQuote(raw) && (serr == nil) != (err == nil) {
			t.Fatalf("AllowSimulated changes the verdict on a hardware quote: %v / %v", serr, err)
		}
		if trimmed, terr := TrimQuote(raw); terr == nil {
			if !bytes.HasPrefix(raw, trimmed) || !allZero(raw[len(trimmed):]) {
				t.Fatal("TrimQuote cut more than zero padding")
			}
			if again, err := TrimQuote(trimmed); err != nil || !bytes.Equal(again, trimmed) {
				t.Fatalf("TrimQuote is not idempotent (%v)", err)
			}
		}
		if err != nil {
			return
		}
		if !bytes.Equal(q.Raw, raw) || q.Simulated != IsSimulatedQuote(raw) {
			t.Fatal("parsed quote does not keep its raw bytes")
		}
		q2, err := ParseQuote(q.Raw, ParseOptions{AllowSimulated: true})
		if err != nil || q2.MRTD != q.MRTD || q2.RTMR != q.RTMR || q2.ReportData != q.ReportData || q2.TDAttributes != q.TDAttributes ||
			q2.XFAM != q.XFAM || q2.TeeTcbSvn != q.TeeTcbSvn || q2.Version != q.Version || q2.MeasurementsHash() != q.MeasurementsHash() {
			t.Fatalf("re-parse differs (%v)", err)
		}
		_ = q.CheckProductionAttributes()
		if q.Simulated {
			if q.Debug() != (q.TDAttributesValue()&tdAttrDebug != 0) {
				t.Fatal("debug flag and TD_ATTRIBUTES disagree")
			}
			if q.RTMR[0] == SimRTMR0 && q.RTMR[1] == SimRTMR1 && q.RTMR[2] == SimRTMR2 {
				mrtd := q.MRTD
				enc := NewSimQuote(SimQuoteParams{Debug: q.Debug(), RTMR3: q.RTMR[3], ReportData: q.ReportData, MRTD: &mrtd})
				if !bytes.Equal(enc, raw) {
					t.Fatalf("two encodings of one simulated quote: %q and %q", raw, enc)
				}
			}
			return
		}
		if q.Version != 4 && q.Version != 5 {
			t.Fatalf("hardware quote version %d", q.Version)
		}
		if strict == nil || strict.Raw == nil {
			t.Fatal("strict parse lost the quote")
		}
		if trimmed, err := TrimQuote(raw); err != nil || !bytes.Equal(trimmed, raw) {
			t.Fatalf("accepted quote has trailing bytes (%v)", err)
		}
	})
}

// lowS returns raw with both ECDSA signatures (the quote's and the QE
// report's) in their low-s form, re-serialized. Each signature also verifies
// as (r, n-s), so these four encodings of one attestation are the only
// variants a verifier cannot refuse; ok is false if raw does not parse.
func lowS(raw []byte) ([]byte, bool) {
	p, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, false
	}
	s, ok := p.(interface {
		GetSignedData() *pb.Ecdsa256BitQuoteV4AuthData
	})
	if !ok {
		return nil, false
	}
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(n, 1)
	norm := func(sig []byte) {
		if len(sig) != 64 {
			return
		}
		v := new(big.Int).SetBytes(sig[32:])
		if v.Cmp(half) > 0 {
			v.Sub(n, v).FillBytes(sig[32:])
		}
	}
	sd := s.GetSignedData()
	norm(sd.GetSignature())
	norm(sd.GetCertificationData().GetQeReportCertificationData().GetQeReportSignature())
	out, err := abi.QuoteToAbiBytes(p)
	return out, err == nil
}

// FuzzVerifyQuote: VerifyQuote never panics, and no quote verifies against
// the recorded collateral except the recorded originals and their ECDSA
// (r, n-s) twins (lowS). Any other mutation that still verified would give
// one attestation more quoteHash values (INTERFACES section 2), or worse,
// other measurements.
func FuzzVerifyQuote(f *testing.F) {
	policy := fuzzPolicy(f)
	verifiers := []*Verifier{
		fuzzVerifier(f, filepath.Join("testdata", "gcp", "pcs"), policy),
		fuzzVerifier(f, filepath.Join("testdata", "pcs", "v5_sample"), DefaultTCBPolicy()),
	}
	originals := map[string]bool{}
	for _, q := range fuzzQuoteFiles(f) {
		f.Add(q)
		for _, v := range verifiers {
			if _, err := v.VerifyQuote(context.Background(), q); err == nil {
				originals[string(q)] = true
			}
		}
	}
	if len(originals) < 2 {
		f.Fatalf("only %d recorded quotes verify offline", len(originals))
	}
	twins := map[string]bool{}
	for q := range originals {
		if l, ok := lowS([]byte(q)); ok {
			twins[string(l)] = true
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, v := range verifiers {
			res, err := v.VerifyQuote(context.Background(), raw)
			if err != nil {
				if !errors.Is(err, ErrQuoteInvalid) && !errors.Is(err, ErrTCBStatus) {
					t.Fatalf("verification error wraps no reason code: %v", err)
				}
				continue
			}
			if originals[string(raw)] {
				continue
			}
			if l, ok := lowS(raw); !ok || !twins[string(l)] {
				t.Fatalf("a quote that is not one of the recorded originals verifies (FMSPC %s, TCB %s, %d bytes, sha256 %x)", res.FMSPC, res.TCBStatus, len(raw), sha256.Sum256(raw))
			}
		}
	})
}

func fuzzEventLogs(tb testing.TB) [][]byte {
	var out [][]byte
	if b, err := os.ReadFile(filepath.Join("testdata", "gcp", "eventlog.json")); err == nil {
		out = append(out, b)
	}
	caps, _ := filepath.Glob(filepath.Join("testdata", "gcp", "captures", "*-getquote*.json"))
	for _, p := range caps {
		var r struct {
			EventLog string `json:"event_log"`
		}
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &r) == nil && r.EventLog != "" {
			out = append(out, []byte(r.EventLog))
		}
	}
	for _, p := range []RuntimeParams{{}, {AppID: [20]byte{1}, ComposeHash: [32]byte{2}, InstanceID: [20]byte{3}}} {
		if b, err := json.Marshal(ExpectedRuntimeEvents(p)); err == nil {
			out = append(out, b)
		}
	}
	if len(out) < 3 {
		tb.Fatalf("only %d event log fixtures", len(out))
	}
	return out
}

// FuzzEventLog: ParseEventLog and the RTMR3 replay never panic and every
// error wraps ErrRTMR3Replay. The replay is the plain fold of sha384 over the
// imr 3 digests. CheckRuntimeEvents accepts a log only if its imr 3 events are
// exactly the Sealed sequence for the attested values, and against the GCP
// capture's RTMR3 it accepts only the captured RTMR3 events.
func FuzzEventLog(f *testing.F) {
	logs := fuzzEventLogs(f)
	for _, l := range logs {
		f.Add(l)
	}
	var golden []Event
	var goldenMR Measurement
	if evs, err := ParseEventLog(logs[0]); err == nil {
		if mr, rt, err := ReplayRTMR3(evs); err == nil {
			golden, goldenMR = rt, mr
		}
	}
	if golden == nil {
		f.Fatal("the GCP event log does not replay")
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		evs, err := ParseEventLog(raw)
		if err != nil {
			if !errors.Is(err, ErrRTMR3Replay) {
				t.Fatalf("ParseEventLog error does not wrap ErrRTMR3Replay: %v", err)
			}
			return
		}
		for i, e := range evs {
			if len(e.Digest) != 96 || strings.ToLower(e.Digest) != e.Digest || len(e.EventPayload)%2 != 0 {
				t.Fatalf("event %d accepted with digest %q payload %q", i, e.Digest, e.EventPayload)
			}
		}
		mr, rt, err := ReplayRTMR3(evs)
		if err != nil {
			if !errors.Is(err, ErrRTMR3Replay) {
				t.Fatalf("ReplayRTMR3 error does not wrap ErrRTMR3Replay: %v", err)
			}
			return
		}
		var want Measurement
		n := 0
		for _, e := range evs {
			if e.IMR != 3 {
				continue
			}
			d, _ := hex.DecodeString(e.Digest)
			h := sha512.New384()
			h.Write(want[:])
			h.Write(d)
			copy(want[:], h.Sum(nil))
			n++
		}
		if mr != want || len(rt) != n {
			t.Fatalf("replay %x over %d events, plain fold %x over %d", mr, len(rt), want, n)
		}
		info, err := CheckRuntimeEvents(evs, mr)
		if err == nil {
			exp := ExpectedRuntimeEvents(RuntimeParams{AppID: info.AppID, ComposeHash: info.ComposeHash, InstanceID: info.InstanceID})
			if len(rt) != len(exp) {
				t.Fatalf("accepted %d runtime events, the sequence has %d", len(rt), len(exp))
			}
			for i := range exp {
				if rt[i].Event != exp[i].Event || rt[i].EventPayload != exp[i].EventPayload || rt[i].Digest != exp[i].Digest || rt[i].EventType != exp[i].EventType {
					t.Fatalf("accepted event %d %+v, the sequence has %+v", i, rt[i], exp[i])
				}
			}
			if info.KeyProvider != KeyProviderPayload || info.StorageFS != StorageFSPayload || !info.StorageEncrypted || info.RTMR3 != mr {
				t.Fatalf("accepted runtime info %+v", info)
			}
		} else if !errors.Is(err, ErrRTMR3Replay) {
			t.Fatalf("CheckRuntimeEvents error does not wrap ErrRTMR3Replay: %v", err)
		}
		if mr == goldenMR {
			if len(rt) != len(golden) {
				t.Fatalf("%d runtime events replay to the capture's RTMR3, the capture has %d", len(rt), len(golden))
			}
			for i := range golden {
				if i >= len(rt) || rt[i].Event != golden[i].Event || rt[i].EventPayload != golden[i].EventPayload {
					t.Fatalf("an event log other than the capture's replays to the capture's RTMR3")
				}
			}
		}
	})
}
