package gcp_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/gcp"
	"github.com/sealedtempo/sealed/key-broker/internal/gcpfake"
)

const keyVersion = "projects/cust-proj-1/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb/cryptoKeyVersions/1"

func setup(t *testing.T) (*gcpfake.Server, gcp.TokenSource) {
	f := gcpfake.New(t, "cust-proj-1", keyVersion, bytes.Repeat([]byte{9}, 32))
	return f, &gcp.MetadataTokenSource{Host: f.Host()}
}

func TestMetadataTokenIsCached(t *testing.T) {
	f, ts := setup(t)
	for range 3 {
		tok, err := ts.Token(context.Background())
		if err != nil || tok != gcpfake.Token {
			t.Fatalf("token %q %v", tok, err)
		}
	}
	if f.TokenCalls != 1 {
		t.Fatalf("%d metadata calls, want 1", f.TokenCalls)
	}
	now := time.Now()
	ts2 := &gcp.MetadataTokenSource{Host: f.Host(), Now: func() time.Time { return now }}
	_, _ = ts2.Token(context.Background())
	now = now.Add(time.Hour)
	_, _ = ts2.Token(context.Background())
	if f.TokenCalls != 3 {
		t.Fatalf("expired token not refreshed (%d calls)", f.TokenCalls)
	}
}

func TestSecretManager(t *testing.T) {
	f, ts := setup(t)
	sm, err := gcp.NewSecretManager("cust-proj-1", ts)
	if err != nil {
		t.Fatal(err)
	}
	sm.Endpoint = f.URL
	f.SetSecret("sealed-crm-APP_SECRET", "s3cret\nwith newline")
	v, err := sm.Access(context.Background(), "sealed-crm-APP_SECRET")
	if err != nil || string(v) != "s3cret\nwith newline" {
		t.Fatalf("access %q %v", v, err)
	}
	if _, err := sm.Access(context.Background(), "sealed-crm-MISSING"); !errors.Is(err, keybroker.ErrSecretNotFound) {
		t.Fatalf("missing: %v", err)
	}
	f.SetSecret("sealed-crm-OFF", "x")
	f.DisableSecret("sealed-crm-OFF")
	if _, err := sm.Access(context.Background(), "sealed-crm-OFF"); !errors.Is(err, keybroker.ErrSecretNotFound) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := sm.Access(context.Background(), "../../other"); err == nil {
		t.Fatal("path-like secret id accepted")
	}
	// Transient 503s are retried.
	f.FailNext = 2
	if v, err := sm.Access(context.Background(), "sealed-crm-APP_SECRET"); err != nil || len(v) == 0 {
		t.Fatalf("after retries: %v", err)
	}
	f.FailNext = 3
	if _, err := sm.Access(context.Background(), "sealed-crm-APP_SECRET"); err == nil || errors.Is(err, keybroker.ErrSecretNotFound) {
		t.Fatalf("persistent 503: %v", err)
	}
	f.FailNext = 0
	f.CorruptCRC = true
	if _, err := sm.Access(context.Background(), "sealed-crm-APP_SECRET"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt payload: %v", err)
	}
	// Errors never carry the value or the token.
	f.CorruptCRC = false
	sm.Tokens = gcp.StaticToken("wrong-token")
	_, err = sm.Access(context.Background(), "sealed-crm-APP_SECRET")
	if err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("unauthenticated: %v", err)
	}
	if _, err := gcp.NewSecretManager("Not A Project", ts); err == nil {
		t.Fatal("bad project accepted")
	}
}

func TestKMSMAC(t *testing.T) {
	f, ts := setup(t)
	k, err := gcp.NewKMSMAC(keyVersion, ts)
	if err != nil {
		t.Fatal(err)
	}
	k.Endpoint = f.URL
	cust := common.HexToAddress("0x00000000000000000000000000000000000000c1")
	data := keybroker.KeyMessage(keybroker.DiskKeyTag, cust, [32]byte{7})
	mac, err := k.MAC(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, f.MACKey)
	h.Write(data)
	if !bytes.Equal(mac, h.Sum(nil)) {
		t.Fatal("mac differs from HMAC-SHA256")
	}
	// The broker's key derivation over KMS.
	keys, err := keybroker.DeriveKeys(context.Background(), k, cust, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	local, _ := keybroker.NewLocalHMAC(f.MACKey)
	want, _ := keybroker.DeriveKeys(context.Background(), local, cust, [32]byte{7})
	if keys != want {
		t.Fatal("KMS and local derivations differ")
	}
	// A response for another key version is refused.
	k2, _ := gcp.NewKMSMAC(strings.Replace(keyVersion, "/1", "/2", 1), ts)
	k2.Endpoint = f.URL
	if _, err := k2.MAC(context.Background(), data); err == nil {
		t.Fatal("unknown key version accepted")
	}
}

func TestKMSKeyVersion(t *testing.T) {
	key := "projects/p/locations/l/keyRings/r/cryptoKeys/k"
	if v, err := gcp.KMSKeyVersion(key, "1"); err != nil || v != key+"/cryptoKeyVersions/1" {
		t.Fatalf("%q %v", v, err)
	}
	if v, err := gcp.KMSKeyVersion(key+"/cryptoKeyVersions/4", "1"); err != nil || v != key+"/cryptoKeyVersions/4" {
		t.Fatalf("%q %v", v, err)
	}
	for _, bad := range []struct{ k, v string }{{key, "0"}, {key, "x"}, {"projects/p/keyRings/r", "1"}, {"", "1"}} {
		if _, err := gcp.KMSKeyVersion(bad.k, bad.v); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestLoggingSink(t *testing.T) {
	f, ts := setup(t)
	env := map[string]string{"K_SERVICE": "sealed-key-broker", "K_REVISION": "sealed-key-broker-00001-abc", "K_CONFIGURATION": "sealed-key-broker"}
	res := gcp.CloudRunResource("cust-proj-1", "us-central1", func(k string) string { return env[k] })
	l, err := gcp.NewLoggingSink("cust-proj-1", "", res, ts)
	if err != nil {
		t.Fatal(err)
	}
	l.Endpoint = f.URL
	d := &keybroker.Decision{Time: time.Unix(1_800_000_000, 0), RequestID: "abc123", Decision: keybroker.DecisionDenied,
		Reason: keybroker.ReasonStackNotApproved, HTTPStatus: 403, Hashes: keybroker.Hashes{StackHash: "0x01"},
		Checks: []keybroker.Check{{Name: keybroker.CheckStackApproved, Reason: keybroker.ReasonStackNotApproved}}}
	if err := l.Write(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	es := f.Entries()
	if len(es) != 1 {
		t.Fatalf("%d entries", len(es))
	}
	e := es[0]
	jp := e["jsonPayload"].(map[string]any)
	labels := e["labels"].(map[string]any)
	resource := e["resource"].(map[string]any)
	if e["logName"] != "projects/cust-proj-1/logs/sealed-key-broker-decisions" || e["severity"] != "WARNING" || e["insertId"] != "abc123" ||
		labels["reason"] != "stack_not_approved" || jp["reason"] != "stack_not_approved" || jp["message"] == nil ||
		resource["type"] != "cloud_run_revision" || resource["labels"].(map[string]any)["service_name"] != "sealed-key-broker" {
		t.Fatalf("entry %v", e)
	}
	f.LoggingDown = true
	if err := l.Write(context.Background(), d); err == nil {
		t.Fatal("a refused write reported success")
	}
	if got := gcp.CloudRunResource("p1-abcde", "r", func(string) string { return "" }); got.Type != "global" {
		t.Fatalf("resource off Cloud Run %+v", got)
	}
}

// TestLoggingSinkBatch (kb-6): WriteBatch sends many decisions in one entries:write call, with partialSuccess, and
// splits the batch when it would exceed MaxBatchBytes. Single writes keep partialSuccess off.
func TestLoggingSinkBatch(t *testing.T) {
	f, ts := setup(t)
	l, err := gcp.NewLoggingSink("cust-proj-1", "", gcp.CloudRunResource("cust-proj-1", "us-central1", func(string) string { return "" }), ts)
	if err != nil {
		t.Fatal(err)
	}
	l.Endpoint = f.URL
	mk := func(i int, detail string) *keybroker.Decision {
		return &keybroker.Decision{Time: time.Unix(1_800_000_000, 0), RequestID: fmt.Sprintf("req%03d", i),
			Decision: keybroker.DecisionDenied, Reason: keybroker.ReasonQuoteInvalid, HTTPStatus: 403, Detail: detail}
	}
	var small []*keybroker.Decision
	for i := range keybroker.MaxLogBatch {
		small = append(small, mk(i, "junk quote"))
	}
	if err := l.WriteBatch(context.Background(), small); err != nil {
		t.Fatal(err)
	}
	if f.LoggingCalls != 1 || len(f.Entries()) != keybroker.MaxLogBatch || !f.PartialSuccess[0] {
		t.Fatalf("%d calls, %d entries, partialSuccess %v; want one call with %d entries", f.LoggingCalls, len(f.Entries()), f.PartialSuccess, keybroker.MaxLogBatch)
	}
	if e := f.Entries()[3]; e["insertId"] != small[3].RequestID || e["jsonPayload"].(map[string]any)["reason"] != keybroker.ReasonQuoteInvalid {
		t.Fatalf("entry %v", e)
	}

	// Six entries of 1 MiB each do not fit in one 4 MiB call.
	var big []*keybroker.Decision
	for i := range 6 {
		big = append(big, mk(i, strings.Repeat("x", 1<<20)))
	}
	calls := f.LoggingCalls
	if err := l.WriteBatch(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	if n := f.LoggingCalls - calls; n < 2 || n > 3 || len(f.Entries()) != keybroker.MaxLogBatch+6 {
		t.Fatalf("%d calls, %d entries for 6 MiB of entries", n, len(f.Entries()))
	}

	if err := l.Write(context.Background(), mk(0, "one")); err != nil {
		t.Fatal(err)
	}
	if f.PartialSuccess[len(f.PartialSuccess)-1] {
		t.Fatal("a single write set partialSuccess")
	}
	f.LoggingDown = true
	if err := l.WriteBatch(context.Background(), small[:2]); err == nil {
		t.Fatal("a refused batch reported success")
	}
}

// TestMetadataRegion reads the Cloud Run region for the log resource (the bootstrap does not set SEALED_GCP_REGION).
func TestMetadataRegion(t *testing.T) {
	f, _ := setup(t)
	r, err := gcp.MetadataRegion(context.Background(), f.Host(), nil)
	if err != nil || r != "us-east5" {
		t.Fatalf("region %q %v", r, err)
	}
	f.Region = "garbage"
	if _, err := gcp.MetadataRegion(context.Background(), f.Host(), nil); err == nil {
		t.Fatal("malformed region accepted")
	}
}
