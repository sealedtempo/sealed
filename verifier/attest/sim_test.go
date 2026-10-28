package attest

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSimQuoteRoundTrip(t *testing.T) {
	var rtmr3 Measurement
	rtmr3[0] = 0x99
	var rd ReportData
	rd[1] = 0x42
	raw := NewSimQuote(SimQuoteParams{RTMR3: rtmr3, ReportData: rd})

	wantPrefix := `SEALEDSIM1{"debug":false,"mrtd":"` + strings.Repeat("11", 48) + `","reportData":"00` + "42"
	if !strings.HasPrefix(string(raw), wantPrefix) {
		t.Fatalf("unexpected encoding: %s", raw)
	}
	if !strings.HasSuffix(string(raw), `,"schema":"sealed-sim-quote/v1"}`) {
		t.Fatalf("unexpected encoding: %s", raw)
	}

	if _, err := ParseQuote(raw, ParseOptions{}); !errors.Is(err, ErrSimulatedNotAllowed) {
		t.Fatalf("simulated quote parsed without AllowSimulated: %v", err)
	}
	q, err := ParseQuote(raw, ParseOptions{AllowSimulated: true})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Simulated || q.Version != 0 || q.Debug() {
		t.Fatalf("flags: %+v", q)
	}
	if q.MRTD != SimMRTD || q.RTMR[0] != SimRTMR0 || q.RTMR[1] != SimRTMR1 || q.RTMR[2] != SimRTMR2 || q.RTMR[3] != rtmr3 {
		t.Fatal("measurements differ")
	}
	if q.ReportData != rd {
		t.Fatal("report data differs")
	}
	if q.MeasurementsHash() != SimMeasurementsHash(false) {
		t.Fatal("measurementsHash")
	}
}

func TestSimQuoteDebugVariant(t *testing.T) {
	q, err := ParseQuote(NewSimQuote(SimQuoteParams{Debug: true}), ParseOptions{AllowSimulated: true})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Debug() || q.MRTD != SimMRTDDebug {
		t.Fatal("debug variant not flagged")
	}
	if err := q.CheckProductionAttributes(); !errors.Is(err, ErrTDAttributes) {
		t.Fatal("debug sim quote passes production attribute check")
	}
	if q.MeasurementsHash() != SimMeasurementsHash(true) {
		t.Fatal("debug measurementsHash")
	}
}

func TestSimQuoteRejectsTampering(t *testing.T) {
	good := string(NewSimQuote(SimQuoteParams{}))
	body := strings.TrimPrefix(good, SimQuotePrefix)
	cases := map[string]string{
		"not canonical":  SimQuotePrefix + strings.Replace(body, `{"debug"`, `{ "debug"`, 1),
		"unknown field":  SimQuotePrefix + strings.Replace(body, `{"debug"`, `{"abc":1,"debug"`, 1),
		"missing schema": SimQuotePrefix + strings.Replace(body, `,"schema":"sealed-sim-quote/v1"`, ``, 1),
		"wrong schema":   strings.Replace(good, "sealed-sim-quote/v1", "sealed-sim-quote/v2", 1),
		"short rtmr0":    strings.Replace(good, `"rtmr0":"2222`, `"rtmr0":"22`, 1),
		"bad hex":        strings.Replace(good, `"rtmr1":"33`, `"rtmr1":"zz`, 1),
		"not json":       SimQuotePrefix + "{",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseQuote([]byte(in), ParseOptions{AllowSimulated: true}); !errors.Is(err, ErrQuoteInvalid) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
}

func TestVerifierSimulatedGate(t *testing.T) {
	raw := NewSimQuote(SimQuoteParams{})
	strict, err := NewVerifier(VerifierOptions{Getter: offlineGetter{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.VerifyQuote(context.Background(), raw); !errors.Is(err, ErrSimulatedNotAllowed) {
		t.Fatalf("strict verifier: %v", err)
	}
	dev, err := NewVerifier(VerifierOptions{AllowSimulated: true, Getter: offlineGetter{}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := dev.VerifyQuote(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Simulated || !res.Quote.Simulated || res.TCBStatus != "Simulated" {
		t.Fatalf("result not flagged simulated: %+v", res)
	}
	// A dev verifier still verifies real quotes for real (and fails closed offline).
	if _, err := dev.VerifyQuote(context.Background(), readQuote(t, "v5_sample")); err == nil {
		t.Fatal("real quote verified with no collateral")
	}
	if bytes.HasPrefix(readQuote(t, "v5_sample"), []byte(SimQuotePrefix)) {
		t.Fatal("fixture misdetected as simulated")
	}
}
