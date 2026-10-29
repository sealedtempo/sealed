// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealedtempo/sealed/verifier/attest"
)

// makePE builds a small, valid PE32+ image with two sections, a certificate table and trailing data, so every
// branch of the Authenticode computation is exercised.
func makePE() []byte {
	const (
		lfanew    = 0x40
		optSize   = 240
		headers   = 0x200
		secAOff   = 0x200
		secASize  = 0x30
		secBOff   = 0x240
		secBSize  = 0x10
		certSize  = 0x18
		trailSize = 0x0d
	)
	data := make([]byte, secBOff+secBSize+trailSize+certSize)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:], lfanew)
	copy(data[lfanew:], "PE\x00\x00")
	coff := lfanew + 4
	binary.LittleEndian.PutUint16(data[coff:], 0x8664)
	binary.LittleEndian.PutUint16(data[coff+2:], 2) // sections
	binary.LittleEndian.PutUint16(data[coff+16:], optSize)
	opt := coff + 20
	binary.LittleEndian.PutUint16(data[opt:], 0x20b) // PE32+
	binary.LittleEndian.PutUint32(data[opt+60:], headers)
	binary.LittleEndian.PutUint32(data[opt+64:], 0xdeadbeef) // checksum, excluded from the hash
	certDir := opt + 112 + 4*8
	certAt := secBOff + secBSize + trailSize
	binary.LittleEndian.PutUint32(data[certDir:], uint32(certAt))
	binary.LittleEndian.PutUint32(data[certDir+4:], certSize)
	sec := opt + optSize
	// Section table in reverse file order, to check sorting.
	copy(data[sec:], ".b\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint32(data[sec+16:], secBSize)
	binary.LittleEndian.PutUint32(data[sec+20:], secBOff)
	copy(data[sec+40:], ".a\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint32(data[sec+40+16:], secASize)
	binary.LittleEndian.PutUint32(data[sec+40+20:], secAOff)
	for i := secAOff; i < len(data); i++ {
		data[i] = byte(i * 7)
	}
	return data
}

func TestAuthenticodeMatchesDstack(t *testing.T) {
	pe := makePE()
	// Golden values from dstack's os/image/authenticode_hash.py (v0.6.1) run on makePE(); the sha384 one with its
	// hashlib.sha256 replaced by hashlib.sha384.
	const want256 = "053fe85c27424f07321c4ef1f375378c64d6ec9a793e11f29cb8bb2bf71fe9e3"
	const want384 = "960e323d9c46688f1bdf7acf0b325ca40acfd0bf807f2e63c17b8bc270aa4b1818e936f751f77328acf5247f54de3958"
	got256, err := authenticode(pe, sha256.New)
	if err != nil {
		t.Fatal(err)
	}
	got384, err := authenticode(pe, sha512.New384)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got256) != want256 || hex.EncodeToString(got384) != want384 {
		t.Fatalf("sha256 %x\nsha384 %x", got256, got384)
	}
	// The checksum field is not covered.
	pe[0x40+4+20+64] ^= 0xff
	again, _ := authenticode(pe, sha256.New)
	if !bytes.Equal(again, got256) {
		t.Fatal("checksum change altered the digest")
	}
	if _, err := authenticode([]byte("MZ"), sha256.New); err == nil {
		t.Fatal("truncated image accepted")
	}
}

func TestImageIDMatchesSolidity(t *testing.T) {
	var mh [32]byte
	for i := range mh {
		mh[i] = 0x11
	}
	id, err := imageID("sealed-dstack-os", "0.6.1-s1+c3-standard-8", mh)
	if err != nil {
		t.Fatal(err)
	}
	// cast keccak $(cast abi-encode "f(string,string,bytes32)" sealed-dstack-os 0.6.1-s1+c3-standard-8 0x11..11)
	if got := hex0x(id[:]); got != "0x6065478854aec92ccab6429ce758ff4a4fb23f0ee7ad2925c06d630fc093e1c1" {
		t.Fatalf("imageId %s", got)
	}
}

func TestVMConfigMatchesDstackCloud(t *testing.T) {
	got := vmConfig("ab", []byte("x  y\n"), []byte{1, 2})
	// python3 -c 'import json,base64;print(json.dumps({"spec_version":2,"os_image_hash":"ab","gcp_measurement":
	//   {"checksum_file":base64.b64encode(b"x  y\n").decode(),"measurement":base64.b64encode(bytes([1,2])).decode()}}))'
	want := `{"spec_version": 2, "os_image_hash": "ab", "gcp_measurement": {"checksum_file": "eCAgeQo=", "measurement": "AQI="}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestMeasureComposeIsCanonical(t *testing.T) {
	rd := bytes.Repeat([]byte{0xab}, 64)
	b, err := measureCompose(rd)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["runner"] != "bash" || m["key_provider"] != "none" || m["storage_fs"] != "ext4" || m["gateway_enabled"] != false {
		t.Fatalf("compose %s", b)
	}
	if !strings.Contains(m["bash_script"].(string), "rd="+hex.EncodeToString(rd)+"\n") {
		t.Fatal("report data not in the script")
	}
	if bytes.Contains(b, []byte(`&`)) || bytes.HasSuffix(b, []byte("\n")) {
		t.Fatal("compose is not compact canonical JSON")
	}
	// Keys must be sorted: re-encoding the decoded map with sorted keys gives the same bytes.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(m)
	if !bytes.Equal(bytes.TrimRight(buf.Bytes(), "\n"), b) {
		t.Fatal("keys not sorted or not compact")
	}
}

// TestMeasureScriptOutputParses runs the measurement boot script against a fake guest agent and parses the serial
// output it produces, with journald console prefixes and kernel noise in between. It needs GNU coreutils
// (base64 -w0, sha256sum), so it runs on Linux CI and is skipped elsewhere.
func TestMeasureScriptOutputParses(t *testing.T) {
	if out, err := exec.Command("base64", "--help").CombinedOutput(); err != nil || !bytes.Contains(out, []byte("-w")) {
		t.Skip("GNU base64 not available")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not available")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	dir := t.TempDir()
	quote := strings.Repeat("0123456789abcdef", 300)
	events := `[{"imr":0,"event_type":2147483658,"digest":"` + strings.Repeat("11", 48) + `","event":"","event_payload":""},` +
		`{"imr":3,"event_type":134217729,"digest":"` + strings.Repeat("22", 48) + `","event":"compose-hash","event_payload":"00"}]`
	resp, _ := json.Marshal(map[string]string{"quote": quote, "event_log": events, "report_data": "", "vm_config": "{}"})
	fake := "#!/bin/sh\ncat <<'EOF'\n" + string(resp) + "\nEOF\n"
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	rd := bytes.Repeat([]byte{0x5a}, 64)
	compose, _ := measureCompose(rd)
	var m map[string]string
	var raw map[string]any
	json.Unmarshal(compose, &raw)
	m = map[string]string{"bash_script": raw["bash_script"].(string)}
	cmd := exec.Command("bash")
	cmd.Stdin = strings.NewReader(m["bash_script"])
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	var serial bytes.Buffer
	serial.WriteString("[    1.000000] Linux version 6.18.40-dstack\nSEALED-MEASURE Q 00000 stale-block-without-end\n")
	for i, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		fmt.Fprintf(&serial, "[   %d.123456] app-compose.sh[812]: %s\r\n", 20+i, line)
		if i == 3 {
			serial.WriteString("[   21.000001] random: crng init done\n")
		}
	}
	gotQuote, gotEvents, err := parseSerial(&serial)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuote != quote {
		t.Fatal("quote round trip")
	}
	var ev []ccEvent
	if err := json.Unmarshal(gotEvents, &ev); err != nil || len(ev) != 1 || ev[0].IMR != 0 {
		t.Fatalf("events %s (%v): only RTMR0-2 entries are printed", gotEvents, err)
	}
}

func TestParseSerialRejectsCorruption(t *testing.T) {
	q := "abcd"
	e := "W10=" // []
	qs := sha256.Sum256([]byte(q))
	es := sha256.Sum256([]byte(e))
	ok := fmt.Sprintf("SEALED-MEASURE BEGIN v1\nSEALED-MEASURE Q 00000 %s\nSEALED-MEASURE E 00000 %s\nSEALED-MEASURE END %x %x\n", q, e, qs, es)
	if _, _, err := parseSerial(strings.NewReader(ok)); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(ok, "Q 00000 abcd", "Q 00000 abce", 1)
	if _, _, err := parseSerial(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupted quote accepted: %v", err)
	}
	gap := strings.Replace(ok, "Q 00000", "Q 00001", 1)
	if _, _, err := parseSerial(strings.NewReader(gap)); err == nil {
		t.Fatal("missing chunk accepted")
	}
	if _, _, err := parseSerial(strings.NewReader("SEALED-MEASURE FAIL the guest agent returned no quote\n")); err == nil {
		t.Fatal("FAIL line ignored")
	}
}

func TestReplayRTMRs(t *testing.T) {
	d1 := bytes.Repeat([]byte{1}, 48)
	d2 := bytes.Repeat([]byte{2}, 48)
	events := []ccEvent{
		{IMR: 0, EventType: 3, Digest: hex.EncodeToString(d2)}, // EV_NO_ACTION, not extended
		{IMR: 0, EventType: 1, Digest: hex.EncodeToString(d1)},
		{IMR: 2, EventType: 1, Digest: hex.EncodeToString(d1)},
		{IMR: 2, EventType: 1, Digest: hex.EncodeToString(d2)},
		{IMR: 3, EventType: 1, Digest: hex.EncodeToString(d2)}, // RTMR3, ignored here
	}
	got, err := replayRTMRs(events)
	if err != nil {
		t.Fatal(err)
	}
	ext := func(mr, d []byte) []byte {
		h := sha512.New384()
		h.Write(mr)
		h.Write(d)
		return h.Sum(nil)
	}
	zero := make([]byte, 48)
	if !bytes.Equal(got[0][:], ext(zero, d1)) || !bytes.Equal(got[1][:], zero) || !bytes.Equal(got[2][:], ext(ext(zero, d1), d2)) {
		t.Fatal("replay")
	}
}

// gceFixture is the real GCE C3 TDX quote and Intel collateral the verifier package records for its own tests.
func gceFixture(t *testing.T) (quote []byte, pcsDir string, at time.Time) {
	t.Helper()
	base := filepath.Join("..", "..", "..", "..", "..", "verifier", "attest", "testdata")
	raw, err := os.ReadFile(filepath.Join(base, "quotes", "v4_gce_cos113.dat"))
	if err != nil {
		t.Skipf("verifier fixture not available: %v", err)
	}
	src := filepath.Join(base, "pcs", "v4_gce_cos113")
	pcsDir = t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pcsDir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var rec struct {
		RecordedAt int64 `json:"recordedAt"`
	}
	b, _ := os.ReadFile(filepath.Join(src, "recorded.json"))
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	return raw, pcsDir, time.Unix(rec.RecordedAt, 0)
}

func TestMeasureRealGCEQuote(t *testing.T) {
	raw, pcsDir, at := gceFixture(t)
	q, err := attest.ParseQuote(mustTrim(t, raw), attest.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A two-event RTMR1 log whose second event is the UKI digest; the replay cannot match the real quote.
	uki := strings.Repeat("ab", 48)
	events := fmt.Sprintf(`[{"imr":1,"event_type":2147483651,"digest":"%s","event":"","event_payload":""}]`, uki)
	id := &identity{Name: "sealed-dstack-os", Variant: "prod", OSImageHash: "00"}
	id.UKI.AuthenticodeSHA384 = uki
	o := measureOptions{verify: true, collateralDir: pcsDir, offline: true, at: at}
	m, err := measure(context.Background(), raw, []byte(events), q.ReportData[:], id, o)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Quote.Verified || m.Quote.TCBStatus != "OutOfDate" || m.MRTD != hex0x(q.MRTD[:]) || m.RTMR2 != hex0x(q.RTMR[2][:]) {
		t.Fatalf("measurement %+v", m)
	}
	mh := q.MeasurementsHash()
	if m.MeasurementsHash != hex0x(mh[:]) || !m.EventLog.UKIInRTMR1 || m.EventLog.ReplayMatches["rtmr1"] {
		t.Fatalf("measurement %+v", m)
	}
	// A quote over different report data is not this boot's.
	other := bytes.Repeat([]byte{0xee}, 64)
	if _, err := measure(context.Background(), raw, []byte(events), other, id, o); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong report data accepted: %v", err)
	}
	// Corrupt the signed body: verification must fail.
	bad := mustTrim(t, raw)
	bad[200] ^= 1
	if _, err := measure(context.Background(), bad, []byte(events), q.ReportData[:], id, o); err == nil {
		t.Fatal("tampered quote accepted")
	}
}

func mustTrim(t *testing.T, raw []byte) []byte {
	t.Helper()
	q, err := attest.TrimQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(q)
}

func boot(mt string, n int, rtmr0 byte) measurement {
	m := measurement{Schema: measurementSchema, MachineType: mt, Boot: n, OSImageHash: "aa", MeasuredAt: fmt.Sprintf("2026-10-28T00:00:0%dZ", n)}
	m.Quote.Verified = true
	mr := func(b byte) attest.Measurement {
		var x attest.Measurement
		for i := range x {
			x[i] = b
		}
		return x
	}
	mrtd, r0, r1, r2 := mr(1), mr(rtmr0), mr(3), mr(4)
	m.MRTD, m.RTMR0, m.RTMR1, m.RTMR2 = hex0x(mrtd[:]), hex0x(r0[:]), hex0x(r1[:]), hex0x(r2[:])
	mh := attest.MeasurementsHash(mrtd, r0, r1, r2)
	m.MeasurementsHash = hex0x(mh[:])
	return m
}

func TestBuildCatalog(t *testing.T) {
	id := &identity{Name: "sealed-dstack-os-debug", Variant: "debug", IsDebug: true, SealedOSVersion: "0.6.1-s1", OSImageHash: "aa"}
	id.GCETarball.SHA256 = "ff"
	boots := []measurement{boot("c3-standard-8", 1, 2), boot("c3-standard-8", 2, 2), boot("c3-standard-4", 1, 2), boot("c4-standard-8", 1, 9)}
	cat, err := buildCatalog(id, boots, "https://example.invalid/x.tar.gz#sha256=ff")
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Images) != 2 {
		t.Fatalf("images %+v", cat.Images)
	}
	a := cat.Images[0]
	if a.Version != "0.6.1-s1+c3-standard-4.c3-standard-8" || a.Boots != 3 || !a.IsDebug || a.Trust != "tofu" || a.MeasuredAt != "2026-10-28T00:00:02Z" {
		t.Fatalf("entry %+v", a)
	}
	var mh [32]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(a.MeasurementsHash, "0x"))
	copy(mh[:], b)
	want, _ := imageID(a.Name, a.Version, mh)
	if a.ImageID != hex0x(want[:]) {
		t.Fatal("imageId")
	}
	if cat.Images[1].Version != "0.6.1-s1+c4-standard-8" {
		t.Fatalf("second entry %+v", cat.Images[1])
	}
	// Unstable measurements for one machine type cannot be pinned.
	if _, err := buildCatalog(id, []measurement{boot("c3-standard-8", 1, 2), boot("c3-standard-8", 2, 7)}, "u"); err == nil {
		t.Fatal("unstable boots accepted")
	}
	unverified := boot("c3-standard-8", 1, 2)
	unverified.Quote.Verified = false
	if _, err := buildCatalog(id, []measurement{unverified}, "u"); err == nil {
		t.Fatal("unverified quote accepted")
	}
	other := boot("c3-standard-8", 1, 2)
	other.OSImageHash = "bb"
	if _, err := buildCatalog(id, []measurement{other}, "u"); err == nil {
		t.Fatal("measurement of another image accepted")
	}
}

func TestRunDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"nonce"}, &out, &errb); err != nil || len(strings.TrimSpace(out.String())) != 128 {
		t.Fatalf("nonce %q %v", out.String(), err)
	}
	if err := run([]string{"bogus"}, &out, &errb); err == nil {
		t.Fatal("unknown command accepted")
	}
}
