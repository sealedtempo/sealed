// Package auth issues and checks the proxy credentials of callers whose
// config sets proxyAuth (the platform sidecars). Source IPs on a Docker
// bridge can be spoofed by a container with CAP_NET_RAW, so for these
// callers the IP selects the allowlist and the credential proves the
// sender.
//
// The credential cannot sit in the measured config: the compose is public
// (it is served by /attest). Instead egress makes one random token per
// caller at startup and writes it to <dir>/<caller>/token, a volume the
// composer mounts only into egress and that caller. An existing valid token
// is reused, so restarting egress does not break the caller.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// TokenFile is the file name under <dir>/<caller>/.
const TokenFile = "token"

// tokenLen is the hex length of a token (32 random bytes).
const tokenLen = 64

// Tokens holds the credential of every caller that must authenticate.
type Tokens struct {
	byCaller map[string]string
}

// Provision loads or creates a token for each caller under dir.
func Provision(dir string, callers []string) (*Tokens, error) {
	t := &Tokens{byCaller: map[string]string{}}
	if len(callers) == 0 {
		return t, nil
	}
	if dir == "" {
		return nil, errors.New("proxy auth: callers require a credential but no token directory is set")
	}
	for _, name := range callers {
		tok, err := provisionOne(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("proxy auth for %s: %w", name, err)
		}
		t.byCaller[name] = tok
	}
	return t, nil
}

func provisionOne(dir string) (string, error) {
	path := filepath.Join(dir, TokenFile)
	if b, err := os.ReadFile(path); err == nil && validToken(string(b)) {
		return string(b), nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var raw [tokenLen / 2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	// The volume is mounted only into egress and this caller, whose user may
	// differ from egress's, so the file is world-readable inside it.
	if err := tmp.Chmod(0o444); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(tok); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return tok, nil
}

func validToken(s string) bool {
	if len(s) != tokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Required reports whether caller must present a credential.
func (t *Tokens) Required(caller string) bool {
	if t == nil {
		return false
	}
	_, ok := t.byCaller[caller]
	return ok
}

// CheckProxy verifies Proxy-Authorization: Basic base64(<caller>:<token>),
// which HTTP clients send for a proxy URL of the form
// http://<caller>:<token>@172.30.0.2:3128. Callers that do not require a
// credential always pass.
func (t *Tokens) CheckProxy(caller string, h http.Header) bool {
	if !t.Required(caller) {
		return true
	}
	user, pass, ok := basic(h.Get("Proxy-Authorization"))
	return ok && user == caller && t.equal(caller, pass)
}

// CheckBearer verifies Authorization: Bearer <token> (used on GET
// /v1/stats). Callers that do not require a credential always pass.
func (t *Tokens) CheckBearer(caller string, h http.Header) bool {
	if !t.Required(caller) {
		return true
	}
	scheme, tok, ok := strings.Cut(h.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "Bearer") && t.equal(caller, strings.TrimSpace(tok))
}

func (t *Tokens) equal(caller, got string) bool {
	want := t.byCaller[caller]
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func basic(header string) (user, pass string, ok bool) {
	scheme, enc, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}
