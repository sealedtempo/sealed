package auth

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func readToken(t *testing.T, dir, caller string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, caller, TokenFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func proxyHeader(user, pass string) http.Header {
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	return h
}

func TestProvisionWritesAndReusesTokens(t *testing.T) {
	dir := t.TempDir()
	tok, err := Provision(dir, []string{"sealed-agent", "sealed-mpp-payer"})
	if err != nil {
		t.Fatal(err)
	}
	agent := readToken(t, dir, "sealed-agent")
	payer := readToken(t, dir, "sealed-mpp-payer")
	if !validToken(agent) || !validToken(payer) || agent == payer {
		t.Fatalf("tokens %q %q", agent, payer)
	}
	info, err := os.Stat(filepath.Join(dir, "sealed-agent", TokenFile))
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("token mode = %v, %v", info.Mode(), err)
	}
	if !tok.Required("sealed-agent") || tok.Required("alpha") {
		t.Error("Required wrong")
	}
	// A restart keeps the same token, so the caller's copy stays valid.
	again, err := Provision(dir, []string{"sealed-agent", "sealed-mpp-payer"})
	if err != nil {
		t.Fatal(err)
	}
	if !again.CheckProxy("sealed-agent", proxyHeader("sealed-agent", agent)) {
		t.Error("token changed across restarts")
	}
	// A damaged token file is replaced.
	path := filepath.Join(dir, "sealed-agent", TokenFile)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(dir, []string{"sealed-agent"}); err != nil {
		t.Fatal(err)
	}
	if fresh := readToken(t, dir, "sealed-agent"); !validToken(fresh) || fresh == agent {
		t.Errorf("damaged token not replaced: %q", fresh)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "sealed-agent"))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestProvisionNeedsDirectory(t *testing.T) {
	if _, err := Provision("", []string{"sealed-agent"}); err == nil {
		t.Fatal("Provision without a directory succeeded")
	}
	tok, err := Provision("", nil)
	if err != nil || tok.Required("anyone") {
		t.Fatalf("no callers: %v %v", tok, err)
	}
	var nilTokens *Tokens
	if nilTokens.Required("x") || !nilTokens.CheckProxy("x", http.Header{}) {
		t.Error("nil Tokens must require nothing")
	}
}

func TestCheckProxyAndBearer(t *testing.T) {
	dir := t.TempDir()
	tok, err := Provision(dir, []string{"sealed-agent"})
	if err != nil {
		t.Fatal(err)
	}
	good := readToken(t, dir, "sealed-agent")
	if !tok.CheckProxy("sealed-agent", proxyHeader("sealed-agent", good)) {
		t.Fatal("valid credential refused")
	}
	bad := map[string]http.Header{
		"none":       {},
		"wrong user": proxyHeader("alpha", good),
		"wrong pass": proxyHeader("sealed-agent", good[:63]+"0"),
		"empty pass": proxyHeader("sealed-agent", ""),
		"bearer":     {"Proxy-Authorization": {"Bearer " + good}},
		"bad base64": {"Proxy-Authorization": {"Basic !!!"}},
		"no colon":   {"Proxy-Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(good))}},
	}
	for name, h := range bad {
		if tok.CheckProxy("sealed-agent", h) {
			t.Errorf("%s: accepted", name)
		}
	}
	if !tok.CheckProxy("alpha", http.Header{}) {
		t.Error("caller without proxyAuth refused")
	}
	if !tok.CheckBearer("sealed-agent", http.Header{"Authorization": {"Bearer " + good}}) {
		t.Error("valid bearer refused")
	}
	for _, v := range []string{"", "Bearer", "Bearer " + good[:10], "Basic " + good} {
		if tok.CheckBearer("sealed-agent", http.Header{"Authorization": {v}}) {
			t.Errorf("bearer %q accepted", v)
		}
	}
}
