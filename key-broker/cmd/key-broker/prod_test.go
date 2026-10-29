//go:build !sealeddev

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/gcpfake"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
)

// These tests run only in the production build, the one the image ships.

// TestProductionBuildHasNoDevOptions: in the build the image uses (no tags) the dev flags do not exist, even with
// SEALED_DEV_SIM=1.
func TestProductionBuildHasNoDevOptions(t *testing.T) {
	for _, flag := range []string{"--dev-allow-simulated", "--dev-secrets-file=x", "--dev-kms-key-file=x", "--dev-decision-log=x"} {
		_, err := loadConfig([]string{flag}, prodEnv(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Errorf("%s: %v", flag, err)
		}
	}
	// The dev environment variable alone changes nothing: plain HTTP catalogs stay refused.
	if _, err := loadConfig([]string{"--release-asset-base", "http://127.0.0.1/x"}, prodEnv(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard); err == nil {
		t.Fatal("http catalog accepted in the production build")
	}
	// Nor does it unlock other chains (D-060) or tolerate unknown settings.
	if _, err := loadConfig(nil, prodEnv(map[string]string{"SEALED_DEV_SIM": "1", "TEMPO_CHAIN_ID": "31337"}), io.Discard); err == nil {
		t.Fatal("a local chain accepted in the production build")
	}
	if _, err := loadConfig(nil, prodEnv(map[string]string{"SEALED_DEV_SIM": "1", "SEALED_CUSTOMER": "0x1"}), io.Discard); err == nil {
		t.Fatal("an unknown variable accepted in the production build")
	}
}

// TestProductionWiringRefusesSimulatedQuotes runs the production wiring (Secret Manager, KMS and Cloud Logging over
// HTTP against a local fake, metadata-server tokens) with SEALED_DEV_SIM=1 set, and sends a complete simulated
// release: it is refused with quote_invalid, as is a request without a TDX quote (a non-confidential VM), and both
// decisions reach Cloud Logging.
func TestProductionWiringRefusesSimulatedQuotes(t *testing.T) {
	f := gcpfake.New(t, "cust-proj-1", testKeyVersion, bytes.Repeat([]byte{3}, 32))
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	env := prodEnv(map[string]string{
		"SEALED_DEV_SIM":                "1",
		"GCE_METADATA_HOST":             f.Host(),
		"SEALED_SECRETMANAGER_ENDPOINT": f.URL,
		"SEALED_KMS_ENDPOINT":           f.URL,
		"SEALED_LOGGING_ENDPOINT":       f.URL,
		"TEMPO_RPC_URL":                 "http://127.0.0.1:1", // never reached: the quote check fails first
	})
	c, err := loadConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newApp(context.Background(), c, envMap(env), newLogger(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if a.broker.Config().AllowSimulated {
		t.Fatal("the production build allows simulated quotes")
	}
	srv := httptest.NewServer(a.handler)
	defer srv.Close()

	for _, noQuote := range []bool{false, true} {
		var nr keybroker.NonceResponse
		resp, err := http.Get(srv.URL + "/v1/nonce")
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewDecoder(resp.Body).Decode(&nr)
		resp.Body.Close()
		n := common.FromHex(nr.Nonce)
		at := kbtest.NewAttempt(t, s, [32]byte(n))
		if noQuote {
			at.Quote = nil
		}
		resp, err = http.Post(srv.URL+"/v1/release", "application/json", bytes.NewReader(at.Body(t)))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var d keybroker.Denial
		_ = json.Unmarshal(body, &d)
		if resp.StatusCode != 403 || d.Reason != keybroker.ReasonQuoteInvalid {
			t.Fatalf("noQuote=%v: %d %s", noQuote, resp.StatusCode, body)
		}
	}
	if err := a.broker.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	es := f.Entries()
	if len(es) != 2 {
		t.Fatalf("%d Cloud Logging entries, want 2", len(es))
	}
	for _, e := range es {
		if e["labels"].(map[string]any)["reason"] != "quote_invalid" || e["logName"] != "projects/cust-proj-1/logs/sealed-key-broker-decisions" {
			t.Fatalf("entry %v", e)
		}
	}
	if f.TokenCalls != 1 {
		t.Fatalf("%d token fetches, want 1 (cached)", f.TokenCalls)
	}
}
