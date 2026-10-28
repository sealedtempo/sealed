package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	testcases "github.com/google/go-tdx-guest/testing"
)

// recordedTime returns the time the PCS responses in testdata/pcs/<name> were recorded.
func recordedTime(t *testing.T, name string) time.Time {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "pcs", name, "recorded.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		RecordedAt int64 `json:"recordedAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return time.Unix(meta.RecordedAt, 0)
}

// recordedVerifier verifies offline against the recorded collateral of quote `name`, at the recording time plus
// `after`.
func recordedVerifier(t *testing.T, name string, policy TCBPolicy, after time.Duration) *Verifier {
	t.Helper()
	at := recordedTime(t, name)
	getter, err := NewCachingGetter(CacheOptions{
		Dir:   filepath.Join("testdata", "pcs", name),
		TTL:   100 * 365 * 24 * time.Hour,
		Inner: offlineGetter{},
		Now:   func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(VerifierOptions{Getter: getter, TCBPolicy: policy, Now: func() time.Time { return at.Add(after) }})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyRecordedV5UpToDate(t *testing.T) {
	v := recordedVerifier(t, "v5_sample", DefaultTCBPolicy(), 0)
	res, err := v.VerifyQuote(context.Background(), readQuote(t, "v5_sample"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Simulated || res.TCBStatus != "UpToDate" || res.PlatformTCBStatus != "UpToDate" || res.ModuleTCBStatus != "UpToDate" ||
		res.QETCBStatus != "UpToDate" || res.FMSPC != "90c06f000000" {
		t.Fatalf("result %+v", res)
	}
	if res.Quote.Version != 5 {
		t.Fatalf("version %d", res.Quote.Version)
	}
}

func TestVerifyRecordedGCEQuoteTCBPolicy(t *testing.T) {
	raw := gceQuote(t)
	// The real GCE quote verifies, but its TDX TCB is OutOfDate today: the default policy rejects it.
	_, err := recordedVerifier(t, "v4_gce_cos113", DefaultTCBPolicy(), 0).VerifyQuote(context.Background(), raw)
	if !errors.Is(err, ErrTCBStatus) {
		t.Fatalf("err = %v, want ErrTCBStatus", err)
	}
	lenient := TCBPolicy{AllowedStatuses: []string{"UpToDate", "OutOfDate"}}
	res, err := recordedVerifier(t, "v4_gce_cos113", lenient, 0).VerifyQuote(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.TCBStatus != "OutOfDate" || res.PlatformTCBStatus != "OutOfDate" || res.ModuleTCBStatus != "OutOfDate" || res.FMSPC != gceFMSPC {
		t.Fatalf("result %+v", res)
	}
	// The platform level's advisories are reported (and policed), not only the TDX module's.
	if !slices.Equal(res.AdvisoryIDs, gcePlatformAdvisories) || res.TCBDate == "" || res.ModuleTCBDate == "" {
		t.Fatalf("advisories %v dates %q %q", res.AdvisoryIDs, res.TCBDate, res.ModuleTCBDate)
	}
	// With the zero padding of the capture buffer the quote is not canonical and fails before any network use.
	if _, err := recordedVerifier(t, "v4_gce_cos113", lenient, 0).VerifyQuote(context.Background(), readQuote(t, "v4_gce_cos113")); !errors.Is(err, ErrQuoteInvalid) {
		t.Fatalf("padded quote accepted: %v", err)
	}
	strictAdvisories := TCBPolicy{AllowedStatuses: lenient.AllowedStatuses, AllowedAdvisoryIDs: []string{"INTEL-SA-00000"}}
	if _, err := recordedVerifier(t, "v4_gce_cos113", strictAdvisories, 0).VerifyQuote(context.Background(), raw); !errors.Is(err, ErrTCBStatus) {
		t.Fatalf("unlisted advisories accepted: %v", err)
	}
}

func TestVerifyRecordedNoMatchingTCBLevel(t *testing.T) {
	_, err := recordedVerifier(t, "v4_spr_e4", DefaultTCBPolicy(), 0).VerifyQuote(context.Background(), signedQuote(t, "v4_spr_e4"))
	if !errors.Is(err, ErrTCBStatus) {
		t.Fatalf("err = %v, want ErrTCBStatus", err)
	}
}

func TestVerifyRecordedExpiredCollateral(t *testing.T) {
	// TCB info nextUpdate is about 30 days after issue; 60 days later the same bytes must not verify.
	v := recordedVerifier(t, "v5_sample", DefaultTCBPolicy(), 60*24*time.Hour)
	if _, err := v.VerifyQuote(context.Background(), readQuote(t, "v5_sample")); !errors.Is(err, ErrQuoteInvalid) {
		t.Fatalf("expired collateral accepted: %v", err)
	}
}

func TestVerifyTamperedQuote(t *testing.T) {
	raw := bytes.Clone(readQuote(t, "v5_sample"))
	// Flip one report_data byte: header(48) + body descriptor(6) + 520 bytes into the TDX 1.5 body.
	raw[48+6+520] ^= 0x01
	v := recordedVerifier(t, "v5_sample", DefaultTCBPolicy(), 0)
	if _, err := v.VerifyQuote(context.Background(), raw); !errors.Is(err, ErrQuoteInvalid) {
		t.Fatalf("tampered quote accepted: %v", err)
	}
}

func TestVerifyFailsClosedWithoutCollateral(t *testing.T) {
	g, _ := NewCachingGetter(CacheOptions{Inner: offlineGetter{}})
	v, _ := NewVerifier(VerifierOptions{Getter: g, Now: func() time.Time { return recordedTime(t, "v5_sample") }})
	if _, err := v.VerifyQuote(context.Background(), readQuote(t, "v5_sample")); !errors.Is(err, ErrQuoteInvalid) {
		t.Fatalf("verified without collateral: %v", err)
	}
}

// TestVerifyLibrarySampleCollateral uses go-tdx-guest's own sample PCS responses (2023): the chain and collateral
// verify, the sample quote matches no TCB level, so the result is a TCB failure rather than a pass.
func TestVerifyLibrarySampleCollateral(t *testing.T) {
	v, err := NewVerifier(VerifierOptions{
		Getter: testcases.TestGetter,
		Now:    func() time.Time { return time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyQuote(context.Background(), signedQuote(t, "v4_spr_e4")); !errors.Is(err, ErrTCBStatus) {
		t.Fatalf("err = %v, want ErrTCBStatus", err)
	}
}
