//go:build sealeddev

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
)

func TestDevOptionsNeedDevSimEnv(t *testing.T) {
	for _, flag := range []string{"--dev-allow-simulated", "--dev-secrets-file=x", "--dev-kms-key-file=x", "--dev-decision-log=x"} {
		_, err := loadConfig([]string{flag}, prodEnv(nil), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "SEALED_DEV_SIM=1") {
			t.Errorf("%s without SEALED_DEV_SIM=1: %v", flag, err)
		}
	}
	// The dev build without dev options behaves like production.
	c, err := loadConfig(nil, prodEnv(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
	if err != nil || c.dev.any() {
		t.Fatalf("%v %+v", err, c)
	}
	// A dev run tolerates unknown variables of the developer's shell (with a warning) and other chains.
	c, err = loadConfig(nil, prodEnv(map[string]string{"SEALED_DEV_SIM": "1", "TEMPO_PUBLIC_RPC_URL": "https://x", "TEMPO_CHAIN_ID": "31337"}), io.Discard)
	if err != nil || len(c.envWarnings) != 1 || c.ChainID != 31337 {
		t.Fatalf("%v %+v", err, c)
	}
	// Without SEALED_DEV_SIM=1 a dev build is as strict as production.
	if _, err := loadConfig(nil, prodEnv(map[string]string{"TEMPO_PUBLIC_RPC_URL": "https://x"}), io.Discard); err == nil {
		t.Fatal("unknown variable accepted")
	}
}

// TestDevBinaryEndToEnd runs the dev build's real wiring (flags, RPC client, HTTP bundle fetches, dev backends)
// against the real contracts on anvil and a simulated quote, then opens the release like sealed-agent.
func TestDevBinaryEndToEnd(t *testing.T) {
	reg := kbtest.NewAnvilRegistrar(t)
	w := kbtest.NewWorld(t, reg)
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	bundles := kbtest.NewBundleServer(t)
	bundles.Put(t, w.Bundles["notes"])

	dir := t.TempDir()
	secretsFile := filepath.Join(dir, "secrets.json")
	raw, _ := json.Marshal(map[string]string{
		"sealed-notes-APP_SECRET": "dev-app-secret", "sealed-notes-DB_PASSWORD": "dev-db", keybroker.GateSecretID: w.GateHash,
	})
	if err := os.WriteFile(secretsFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "kms.hex")
	logFile := filepath.Join(dir, "decisions.jsonl")
	ct := reg.Contracts()
	args := []string{
		"--customer", kbtest.Customer.Hex(), "--tempo-rpc", reg.URL(), "--chain-id", strconv.FormatUint(reg.ChainID(), 10),
		"--platform-registry", ct.PlatformRegistry.Hex(), "--app-registry", ct.AppRegistry.Hex(), "--deployment-registry", ct.DeploymentRegistry.Hex(),
		"--fee-splitter", kbtest.FeeSplitter.Hex(), "--fee-token", kbtest.FeeToken.Hex(),
		"--release-asset-base", bundles.Base(),
		"--dev-allow-simulated", "--dev-secrets-file", secretsFile, "--dev-kms-key-file", keyFile, "--dev-decision-log", logFile,
	}
	envm := map[string]string{"SEALED_DEV_SIM": "1"}
	env := envMap(envm)
	c, err := loadConfig(args, envm, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var oplog bytes.Buffer
	a, err := newApp(context.Background(), c, env, newLogger(&oplog))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range a.closers {
			_ = f()
		}
	}()
	if !strings.Contains(oplog.String(), `"severity":"WARNING"`) || !strings.Contains(oplog.String(), "DEV MODE: simulated quotes") {
		t.Fatalf("dev mode not announced: %s", oplog.String())
	}
	srv := httptest.NewServer(a.handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/nonce")
	if err != nil {
		t.Fatal(err)
	}
	var nr keybroker.NonceResponse
	_ = json.NewDecoder(resp.Body).Decode(&nr)
	resp.Body.Close()
	at := kbtest.NewAttempt(t, s, [32]byte(common.FromHex(nr.Nonce)))
	resp, err = http.Post(srv.URL+"/v1/release", "application/json", bytes.NewReader(at.Body(t)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("release %d %s", resp.StatusCode, body)
	}
	var rr keybroker.ReleaseResponse
	_ = json.Unmarshal(body, &rr)
	pt := at.Open(t, &rr)
	if pt.Secrets["notes"]["APP_SECRET"] != "dev-app-secret" || pt.Secrets["_gate"]["GATE_PASSWORD_BCRYPT"] != w.GateHash {
		t.Fatalf("secrets %v", pt.Secrets)
	}
	keyHex, _ := os.ReadFile(keyFile)
	key, _ := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	h := hmac.New(sha256.New, key)
	h.Write([]byte(keybroker.DiskKeyTag))
	h.Write(kbtest.Customer[:])
	h.Write(common.FromHex(s.Config["salt"].(string)))
	if pt.DiskKey != "0x"+hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("diskKey is not HMAC(dev key, sealed/disk/v2 || customer || salt)")
	}
	logged, _ := os.ReadFile(logFile)
	if !strings.Contains(string(logged), `"decision":"allowed"`) || !strings.Contains(string(logged), `"simulated":true`) ||
		strings.Contains(string(logged), "dev-app-secret") {
		t.Fatalf("decision log %s", logged)
	}
}
