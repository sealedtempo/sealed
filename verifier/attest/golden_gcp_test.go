package attest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// gcpGolden describes testdata/gcp/expected.json, written when a real quote is captured from a Sealed CVM.
type gcpGolden struct {
	// AttestedAt is the capture time; collateral in testdata/gcp/pcs must be recorded at the same time.
	AttestedAt       int64  `json:"attestedAt"`
	TCBStatus        string `json:"tcbStatus"`
	MeasurementsHash string `json:"measurementsHash"`
	RTMR3            string `json:"rtmr3"`
	ComposeHash      string `json:"composeHash"`
	ReportData       string `json:"reportData"`
	// TDAttributes and XFAM (hex, as in the quote) are chosen by the host and not measured: the capture records
	// what GCP sets for the Sealed image so a per-image pin can be added to PlatformRegistry or the policy.
	TDAttributes string `json:"tdAttributes"`
	XFAM         string `json:"xfam"`
}

// TestRealGCPGolden verifies a real quote and event log captured from a Sealed deployment on GCP C3 TDX.
//
// TODO(gcp): blocked by environment during the build (no GCP project, no TDX hardware). To fill the slot:
//  1. On a booted Sealed CVM, save the quote bytes exactly as sealed-agent puts them in the evidence bundle as
//     testdata/gcp/quote.dat (ParseQuote refuses trailing bytes, so this also checks that the agent sends the
//     signed quote without buffer padding) and its event_log JSON as testdata/gcp/eventlog.json.
//  2. Record collateral: go run ./verifier/internal/tools/pcsrecord -out verifier/attest/testdata/gcp/pcs \
//     verifier/attest/testdata/gcp/quote.dat
//  3. Write testdata/gcp/expected.json (gcpGolden) from the values the key broker logged for that boot.
func TestRealGCPGolden(t *testing.T) {
	dir := filepath.Join("testdata", "gcp")
	expRaw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if os.IsNotExist(err) {
		t.Skip("no real GCP quote captured yet (testdata/gcp is an empty slot; blocked by environment)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var exp gcpGolden
	if err := json.Unmarshal(expRaw, &exp); err != nil {
		t.Fatal(err)
	}
	quote, err := os.ReadFile(filepath.Join(dir, "quote.dat"))
	if err != nil {
		t.Fatal(err)
	}
	logRaw, err := os.ReadFile(filepath.Join(dir, "eventlog.json"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(exp.AttestedAt, 0)
	getter, err := NewCachingGetter(CacheOptions{Dir: filepath.Join(dir, "pcs"), TTL: 100 * 365 * 24 * time.Hour, Inner: offlineGetter{}, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(VerifierOptions{Getter: getter, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.VerifyQuote(context.Background(), quote)
	if err != nil {
		t.Fatal(err)
	}
	if res.TCBStatus != exp.TCBStatus {
		t.Errorf("TCB status %s, want %s", res.TCBStatus, exp.TCBStatus)
	}
	if err := res.Quote.CheckProductionAttributes(); err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(res.Quote.TDAttributes[:]) != exp.TDAttributes || hex.EncodeToString(res.Quote.XFAM[:]) != exp.XFAM {
		t.Errorf("td_attributes %x xfam %x, want %s %s", res.Quote.TDAttributes, res.Quote.XFAM, exp.TDAttributes, exp.XFAM)
	}
	mh := res.Quote.MeasurementsHash()
	if hex.EncodeToString(mh[:]) != exp.MeasurementsHash {
		t.Errorf("measurementsHash %x, want %s", mh, exp.MeasurementsHash)
	}
	if hex.EncodeToString(res.Quote.ReportData[:]) != exp.ReportData {
		t.Errorf("report_data %x, want %s", res.Quote.ReportData, exp.ReportData)
	}
	evs, err := ParseEventLog(logRaw)
	if err != nil {
		t.Fatal(err)
	}
	info, err := CheckRuntimeEvents(evs, res.Quote.RTMR[3])
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(info.ComposeHash[:]) != exp.ComposeHash || hex.EncodeToString(info.RTMR3[:]) != exp.RTMR3 {
		t.Errorf("compose hash %x / rtmr3 %x differ from expected", info.ComposeHash, info.RTMR3)
	}
}
