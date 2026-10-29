package keybroker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sealedtempo/sealed/verifier/attest"
)

// TestTDConfigFields (F7, kb-3): MRCONFIGID and MROWNERCONFIG must be zero (they are on GCE and on dstack on GCP) and
// XFAM must be in tdx.allowed_xfam (D-077); MROWNER is read for the decision log and not pinned.
func TestTDConfigFields(t *testing.T) {
	allowed := attest.DefaultAllowedXFAM()
	// native is each fixture's own XFAM: Google's COS 113 C3 quote predates PKRU (0x600e7), Intel's v5 sample has the
	// value every Sealed capture on C3 shows (0x602e7).
	for name, native := range map[string]uint64{"v4_gce_cos113": 0x600e7, "v5_sample": 0x602e7} {
		raw, err := os.ReadFile(filepath.Join("testdata", "tdx", "quotes", name+".dat"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err = attest.TrimQuote(raw)
		if err != nil {
			t.Fatal(err)
		}
		td, err := readTDConfig(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(td.XFAM) != 8 || len(td.MrOwner) != 48 {
			t.Fatalf("%s: fields %+v", name, td)
		}
		// XFAM follows the 48-byte header, TEE_TCB_SVN (16), MRSEAM (48), MRSIGNERSEAM (48), SEAMATTRIBUTES (8) and
		// TDATTRIBUTES (8); v5 adds a 6-byte body descriptor. MRCONFIGID sits after XFAM and MRTD (48).
		xoff := 48 + 16 + 48 + 48 + 8 + 8
		if name == "v5_sample" {
			xoff += 6
		}
		if got := binary.LittleEndian.Uint64(raw[xoff:]); got != native || !bytes.Equal(raw[xoff:xoff+8], td.XFAM) {
			t.Fatalf("%s: offset %d holds XFAM 0x%x, want 0x%x", name, xoff, got, native)
		}
		err = td.check(allowed)
		if inList := slices.Contains(allowed, native); (err == nil) != inList || err != nil && !errors.Is(err, attest.ErrXFAM) {
			t.Fatalf("%s: XFAM 0x%x in the list %v, check: %v", name, native, inList, err)
		}
		if err := td.check([]uint64{native}); err != nil {
			t.Fatalf("%s: a list holding its XFAM refused it: %v", name, err)
		}

		// The kb-3 repro, inverted: every XFAM outside the list is refused, and 0x602e7 passes.
		withXFAM := func(v uint64) []byte {
			b := bytes.Clone(raw)
			binary.LittleEndian.PutUint64(b[xoff:], v)
			return b
		}
		for _, v := range []uint64{0x602e7 | 1<<8 | 1<<15, 0x602e7 &^ (0x3 << 17), 0x3, 0x600e7, 0} {
			td, err := readTDConfig(withXFAM(v))
			if err != nil {
				t.Fatal(err)
			}
			if err := td.check(allowed); !errors.Is(err, attest.ErrXFAM) || !strings.Contains(err.Error(), "tdx.allowed_xfam") {
				t.Fatalf("%s: XFAM 0x%x: %v", name, v, err)
			}
		}
		base := withXFAM(0x602e7)
		if td, err := readTDConfig(base); err != nil || td.check(allowed) != nil {
			t.Fatalf("%s: XFAM 0x602e7 refused: %v", name, err)
		} else if td.check(nil) == nil {
			t.Fatalf("%s: an empty allowlist accepted XFAM", name)
		}

		off := xoff + 8 + 48
		for _, field := range []int{off, off + 96} { // MRCONFIGID, MROWNERCONFIG
			bad := bytes.Clone(base)
			bad[field] ^= 0x01
			td, err := readTDConfig(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := td.check(allowed); err == nil {
				t.Fatalf("%s: a non-zero field at %d was accepted", name, field)
			}
		}
		// MROWNER (GCP sets it) is not pinned.
		owner := bytes.Clone(base)
		owner[off+48] ^= 0x01
		if td, _ := readTDConfig(owner); td.check(allowed) != nil {
			t.Fatalf("%s: MROWNER refused", name)
		}
	}
}

func TestParseHead(t *testing.T) {
	h, err := parseHead(json.RawMessage(`{"number":"0x2c2b1a3","timestamp":"0x6720a1b0","hash":"0xab","transactions":[{"type":"0x76"}]}`))
	if err != nil || h.Number != 0x2c2b1a3 || h.Time.Unix() != 0x6720a1b0 {
		t.Fatalf("%+v %v", h, err)
	}
	for _, bad := range []string{`null`, ``, `{"number":"0x1"}`, `{"timestamp":"0x1"}`, `{"number":"1","timestamp":"0x1"}`, `{"number":"0x1","timestamp":"0xffffffffffffffff"}`} {
		if _, err := parseHead(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestRPCErrorsAreRedacted: the head reader's errors keep only the RPC URL's scheme and host.
func TestRPCErrorsAreRedacted(t *testing.T) {
	r := newURLRedactor("https://user:pw@rpc.example.com/v2/SECRETKEY?apikey=ALSOSECRET")
	err := r.redact(errors.New(`Post "https://user:pw@rpc.example.com/v2/SECRETKEY?apikey=ALSOSECRET": dial tcp: refused; path /v2/SECRETKEY`))
	for _, leak := range []string{"SECRETKEY", "ALSOSECRET", "pw"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("leak %q in %q", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "https://rpc.example.com") {
		t.Fatalf("host missing: %q", err)
	}
}

func TestClientAddr(t *testing.T) {
	for _, c := range []struct {
		xff  []string
		peer string
		want string
	}{
		{nil, "192.0.2.5:4321", "192.0.2.5"},
		{[]string{"203.0.113.7"}, "10.0.0.1:1", "203.0.113.7"},
		{[]string{"1.2.3.4, 203.0.113.7"}, "10.0.0.1:1", "203.0.113.7"},
		{[]string{"1.2.3.4", "5.6.7.8, 203.0.113.8"}, "10.0.0.1:1", "203.0.113.8"},
		{[]string{"2001:db8:1:2:3:4:5:6"}, "10.0.0.1:1", "2001:db8:1:2:3:4:5:6"},
		{[]string{"not-an-ip"}, "10.0.0.1:1", "not-an-ip"},
	} {
		r := httptest.NewRequest("POST", "/v1/release", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientAddr(r); got != c.want {
			t.Errorf("%v %s: %s, want %s", c.xff, c.peer, got, c.want)
		}
	}
}

func TestLimitKey(t *testing.T) {
	if limitKey("2001:db8:1:2:3:4:5:6") != "2001:db8:1:2::/64" || limitKey("2001:db8:1:2:ffff::1") != "2001:db8:1:2::/64" ||
		limitKey("203.0.113.7") != "203.0.113.7" || limitKey("x") != "x" {
		t.Fatal("limit keys")
	}
}

func TestClientLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newClientLimiter(1, 2, 3, func() time.Time { return now })
	if !l.allow("a") || !l.allow("a") || l.allow("a") {
		t.Fatal("burst of 2")
	}
	now = now.Add(time.Second)
	if !l.allow("a") || l.allow("a") {
		t.Fatal("refill of 1 per second")
	}
	// A full table drops idle buckets, and never refuses because of its own size.
	l.allow("b")
	l.allow("c")
	if !l.allow("d") {
		t.Fatal("a new client refused because the table is full")
	}
	now = now.Add(time.Minute)
	l.allow("e")
	if len(l.buckets) > 3 {
		t.Fatalf("%d buckets", len(l.buckets))
	}
	if newClientLimiter(-1, 1, 1, nil) != nil || !(*clientLimiter)(nil).allow("x") {
		t.Fatal("a disabled limiter must allow")
	}
}

// TestNonceJournal (D-066): with a journal, live nonces survive a restart, consumed ones stay consumed, expired ones
// are dropped, a torn last record is ignored and the file is compacted.
func TestNonceJournal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nonces")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	s, err := OpenNonceStore(NonceOptions{Journal: p, Capacity: 16, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := s.Issue()
	b, _, _ := s.Issue()
	c, _, _ := s.Issue()
	if err := s.Consume(a); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// A crash in the middle of a record write.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.Write([]byte{recIssue, 1, 2, 3})
	f.Close()

	s2, err := OpenNonceStore(NonceOptions{Journal: p, Capacity: 16, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Consume(a); !errors.Is(err, ErrNonceUnknown) {
		t.Fatalf("consumed nonce revived: %v", err)
	}
	if err := s2.Consume(b); err != nil {
		t.Fatalf("live nonce lost: %v", err)
	}
	_ = s2.Close()
	now = now.Add(NonceLifetime)
	s3, err := OpenNonceStore(NonceOptions{Journal: p, Capacity: 16, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if s3.Len() != 0 {
		t.Fatalf("%d nonces after expiry (c=%x)", s3.Len(), c[:2])
	}
	// Compaction keeps the file bounded by the live set.
	for range 200 {
		n, _, err := s3.Issue()
		if err != nil {
			t.Fatal(err)
		}
		_ = s3.Consume(n)
	}
	_ = s3.Close()
	info, _ := os.Stat(p)
	if info.Size() > int64((4*16+1024+2)*recLen) || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal %d bytes, mode %v", info.Size(), info.Mode().Perm())
	}
	_ = os.Chmod(p, 0o644)
	if _, err := OpenNonceStore(NonceOptions{Journal: p, Now: clock}); err == nil {
		t.Fatal("a journal readable by others was accepted")
	}
}

// TestNonceJournalWriteFailure: a nonce whose consumption cannot be recorded is not usable (503, not a release).
func TestNonceJournalWriteFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nonces")
	s, err := OpenNonceStore(NonceOptions{Journal: p})
	if err != nil {
		t.Fatal(err)
	}
	n, _, _ := s.Issue()
	_ = s.journal.f.Close() // writes now fail
	if err := s.Consume(n); !errors.Is(err, ErrNonceStore) {
		t.Fatalf("consume: %v", err)
	}
	if err := s.Consume(n); !errors.Is(err, ErrNonceUnknown) {
		t.Fatalf("second consume: %v", err)
	}
	if _, _, err := s.Issue(); !errors.Is(err, ErrNonceStore) {
		t.Fatalf("issue: %v", err)
	}
}

// TestIntelRoot: the embedded root is the one go-tdx-guest trusts.
func TestIntelRoot(t *testing.T) {
	if _, err := IntelRootPool(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(intelRootPEM, "BEGIN CERTIFICATE") {
		t.Fatal("not PEM")
	}
}
