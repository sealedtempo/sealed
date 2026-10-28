package keybroker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeriveKeys(t *testing.T) {
	m, err := NewLocalHMAC(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a, err := DeriveKeys(context.Background(), m, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveKeys(context.Background(), m, [32]byte{1})
	c, _ := DeriveKeys(context.Background(), m, [32]byte{2})
	if a != b {
		t.Fatal("not deterministic")
	}
	if a.DiskKey == c.DiskKey || a.SignerSeed == c.SignerSeed || a.DiskKey == a.SignerSeed {
		t.Fatal("keys not separated by deploymentId and tag")
	}
	if _, err := NewLocalHMAC(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := DeriveKeys(context.Background(), constMAC{}, [32]byte{}); err == nil {
		t.Fatal("a MAC that ignores its input was accepted")
	}
}

type constMAC struct{}

func (constMAC) MAC(context.Context, []byte) ([]byte, error) { return make([]byte, 32), nil }

func TestFileHMAC(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dev-hmac")
	a, err := LoadOrCreateFileHMAC(p)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	b, err := LoadOrCreateFileHMAC(p)
	if err != nil {
		t.Fatal(err)
	}
	ma, _ := a.MAC(context.Background(), []byte("x"))
	mb, _ := b.MAC(context.Background(), []byte("x"))
	if !bytes.Equal(ma, mb) {
		t.Fatal("the dev key did not persist")
	}
	_ = os.Chmod(p, 0o644)
	if _, err := LoadOrCreateFileHMAC(p); err == nil {
		t.Fatal("a world-readable key file was accepted")
	}
}

func TestJSONLinesLog(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLinesLog(&buf)
	d := &Decision{Time: time.Unix(1, 0).UTC(), RequestID: "r1", Decision: DecisionDenied, Reason: ReasonBadNonce, HTTPStatus: 403,
		Checks: []Check{{Name: CheckNonce, OK: false, Reason: ReasonBadNonce}}}
	if err := l.Write(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	d2 := &Decision{RequestID: "r2", Decision: DecisionAllowed, HTTPStatus: 200, Hashes: Hashes{StackHash: "0xab"}}
	_ = l.Write(context.Background(), d2)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got["severity"] != "WARNING" || got["reason"] != "bad_nonce" || got["requestId"] != "r1" || got["message"] != "key release denied: bad_nonce" {
		t.Fatalf("entry %v", got)
	}
	_ = json.Unmarshal([]byte(lines[1]), &got)
	if got["severity"] != "NOTICE" {
		t.Fatalf("allowed severity %v", got["severity"])
	}

	p := filepath.Join(t.TempDir(), "decisions.jsonl")
	f, err := OpenJSONLinesLog(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Write(context.Background(), d)
	_ = f.Close()
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), `"requestId":"r1"`) {
		t.Fatalf("file %s", raw)
	}
}

func TestParseRequestBounds(t *testing.T) {
	good := func() map[string]any {
		h32 := "0x" + strings.Repeat("ab", 32)
		return map[string]any{"nonce": h32, "ephemeralPub": h32, "imageId": h32, "quote": "0x00", "eventLog": []any{},
			"config": map[string]any{}, "appCompose": "{}", "releaseIds": []any{h32}}
	}
	if _, err := parseRequest(good()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(m map[string]any){
		"quote too large":     func(m map[string]any) { m["quote"] = "0x" + strings.Repeat("00", MaxQuoteBytes+1) },
		"quote not hex":       func(m map[string]any) { m["quote"] = "0xzz" },
		"quote without 0x":    func(m map[string]any) { m["quote"] = "00" },
		"too many releaseIds": func(m map[string]any) { m["releaseIds"] = make([]any, 17) },
		"empty releaseIds":    func(m map[string]any) { m["releaseIds"] = []any{} },
		"short releaseId":     func(m map[string]any) { m["releaseIds"] = []any{"0x00"} },
		"ephemeralPub short":  func(m map[string]any) { m["ephemeralPub"] = "0x00" },
		"config not object":   func(m map[string]any) { m["config"] = "x" },
		"eventLog not array":  func(m map[string]any) { m["eventLog"] = map[string]any{} },
		"event not object":    func(m map[string]any) { m["eventLog"] = []any{"x"} },
		"empty appCompose":    func(m map[string]any) { m["appCompose"] = "" },
		"imageId number":      func(m map[string]any) { m["imageId"] = int64(1) },
	} {
		m := good()
		mutate(m)
		if _, err := parseRequest(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
