package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// gcpMachineDirs are the follow-up captures to the runtime spike (testdata/gcp itself is c3-standard-4 VM 1): one
// fresh VM per entry, booted from the same upstream dstack 0.6.1 image with the same shared and data disk images as
// the spike (byte-identical app-compose.json, .sys-config.json and .instance_info). So every difference between
// them comes from the VM, not from the inputs. See testdata/gcp/<dir>/README.md. D-016: never register them.
var gcpMachineDirs = []string{"c3-standard-4-2", "c3-standard-8-1"}

// gcpMachineGolden describes testdata/gcp/<machine type>-<n>/expected.json.
type gcpMachineGolden struct {
	MachineType string `json:"machineType"`
	VCPUs       int    `json:"vcpus"`
	MemoryGiB   int    `json:"memoryGiB"`
	Captures    []struct {
		Name       string    `json:"name"`
		CapturedAt time.Time `json:"capturedAt"`
	} `json:"captures"`
	ReportDataTag     string   `json:"reportDataTag"`
	QuoteVersion      uint32   `json:"quoteVersion"`
	SignedQuoteLength int      `json:"signedQuoteLength"`
	GetQuoteLength    int      `json:"getQuoteLength"`
	FMSPC             string   `json:"fmspc"`
	TCBStatus         string   `json:"tcbStatus"`
	PlatformTCBStatus string   `json:"platformTcbStatus"`
	ModuleTCBStatus   string   `json:"moduleTcbStatus"`
	QETCBStatus       string   `json:"qeTcbStatus"`
	AdvisoryIDs       []string `json:"advisoryIds"`
	// QuoteHash is sha256 of quote.dat, the trimmed boot1-getquote1 quote.
	QuoteHash        string `json:"quoteHash"`
	MRTD             string `json:"mrtd"`
	RTMR0            string `json:"rtmr0"`
	RTMR1            string `json:"rtmr1"`
	RTMR2            string `json:"rtmr2"`
	RTMR3            string `json:"rtmr3"`
	MeasurementsHash string `json:"measurementsHash"`
	// MROwner, MRSEAM and TEE_TCB_SVN are TD report fields the verifier does not use; the test reads them from the
	// raw quote to record what is per instance and what is per platform.
	MROwner      string `json:"mrowner"`
	MRSEAM       string `json:"mrseam"`
	TeeTcbSvn    string `json:"teeTcbSvn"`
	TDAttributes string `json:"tdAttributes"`
	XFAM         string `json:"xfam"`
	ComposeHash  string `json:"composeHash"`
	AppID        string `json:"appId"`
	InstanceID   string `json:"instanceId"`
	// PCKPPID is the PPID in the quote's leaf PCK certificate: Intel's id of the physical platform.
	PCKPPID string `json:"pckPpid"`
}

// Offsets of TD report fields in a v4 quote that Quote does not expose: header (48) + offset in the TD 1.0 body.
const (
	v4MRSEAMOffset  = 48 + 16
	v4MROwnerOffset = 48 + 16 + 48 + 48 + 8 + 8 + 8 + 48 + 48
)

// gcpMachineCapture is one verified capture of a machine-type directory.
type gcpMachineCapture struct {
	quote  *Quote
	events []Event
	info   *RuntimeInfo
}

// sameEvent compares two event log entries by value (Event.Version is a pointer).
func sameEvent(a, b Event) bool {
	va, vb := 1, 1
	if a.Version != nil {
		va = *a.Version
	}
	if b.Version != nil {
		vb = *b.Version
	}
	return a.IMR == b.IMR && a.EventType == b.EventType && a.Digest == b.Digest && a.Event == b.Event &&
		a.EventPayload == b.EventPayload && va == vb
}

func mrOwner(q *Quote) []byte { return q.Raw[v4MROwnerOffset : v4MROwnerOffset+MeasurementSize] }
func mrSEAM(q *Quote) []byte  { return q.Raw[v4MRSEAMOffset : v4MRSEAMOffset+MeasurementSize] }

// pckPPID returns the PPID (platform provisioning id) of the leaf PCK certificate in the quote's certification
// data. Two quotes with different PPIDs come from different physical platforms.
func pckPPID(t *testing.T, q *Quote) string {
	t.Helper()
	i := bytes.Index(q.Raw, []byte("-----BEGIN CERTIFICATE-----"))
	if i < 0 {
		t.Fatal("no PCK certificate chain in the quote")
	}
	blk, _ := pem.Decode(q.Raw[i:])
	if blk == nil {
		t.Fatal("PCK leaf certificate is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "Intel SGX PCK Certificate" {
		t.Fatalf("leaf certificate %q", c.Subject.CommonName)
	}
	ext, err := pcs.PckCertificateExtensions(c)
	if err != nil {
		t.Fatal(err)
	}
	return ext.PPID
}

func readMachineFile(t *testing.T, dir, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(gcpDir, dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readMachineGolden(t *testing.T, dir string) gcpMachineGolden {
	t.Helper()
	var exp gcpMachineGolden
	if err := json.Unmarshal(readMachineFile(t, dir, "expected.json"), &exp); err != nil {
		t.Fatal(err)
	}
	if len(exp.Captures) == 0 || exp.MachineType == "" || !strings.HasPrefix(dir, exp.MachineType+"-") {
		t.Fatalf("%s/expected.json: machine type %q, %d captures", dir, exp.MachineType, len(exp.Captures))
	}
	return exp
}

// verifyMachineDir verifies every capture of dir the way the verifier and the key broker do (offline, against the
// collateral recorded in dir/pcs right after the capture, with the config/defaults.yaml policy), checks the event
// log and /Info against the quote, and returns the boot1-getquote1 capture.
func verifyMachineDir(t *testing.T, dir string, appCompose []byte) (gcpMachineGolden, gcpMachineCapture) {
	t.Helper()
	exp := readMachineGolden(t, dir)
	ctx := context.Background()
	pcsDir := filepath.Join(gcpDir, dir, "pcs")
	verifiedAt := recordedTimeDir(t, pcsDir)
	v := recordedVerifierDir(t, pcsDir, repoTCBPolicy(t), 0)
	stackHash := sha256.Sum256(appCompose)
	hexEq(t, dir+" composeHash", stackHash[:], exp.ComposeHash)

	var first gcpMachineCapture
	for i, c := range exp.Captures {
		if c.CapturedAt.IsZero() || c.CapturedAt.After(verifiedAt) {
			t.Fatalf("%s/%s: capturedAt %v must be set and not after the collateral recording time %v", dir, c.Name, c.CapturedAt, verifiedAt)
		}
		var gq getQuoteResponse
		if err := json.Unmarshal(readMachineFile(t, dir, filepath.Join("captures", c.Name+".json")), &gq); err != nil {
			t.Fatal(err)
		}
		boot, k, _ := strings.Cut(c.Name, "-getquote")
		nonce, err := hex.DecodeString(strings.TrimSpace(string(readMachineFile(t, dir, filepath.Join("captures", boot+"-nonce"+k+".txt")))))
		if err != nil {
			t.Fatal(err)
		}
		padded, err := hex.DecodeString(gq.Quote)
		if err != nil {
			t.Fatal(err)
		}
		if len(padded) != exp.GetQuoteLength {
			t.Fatalf("%s/%s: GetQuote returned %d bytes, want %d", dir, c.Name, len(padded), exp.GetQuoteLength)
		}
		if _, err := v.VerifyQuote(ctx, padded); err == nil {
			t.Fatalf("%s/%s: the padded GetQuote bytes verified", dir, c.Name)
		}
		signed, err := TrimQuote(padded)
		if err != nil {
			t.Fatal(err)
		}
		if len(signed) != exp.SignedQuoteLength || !allZero(padded[len(signed):]) {
			t.Fatalf("%s/%s: signed quote %d bytes, want %d", dir, c.Name, len(signed), exp.SignedQuoteLength)
		}
		res, err := v.VerifyQuote(ctx, signed)
		if err != nil {
			t.Fatalf("%s/%s: %v", dir, c.Name, err)
		}
		q := res.Quote
		if res.Simulated || q.Version != exp.QuoteVersion || res.FMSPC != exp.FMSPC || res.TCBStatus != exp.TCBStatus ||
			res.PlatformTCBStatus != exp.PlatformTCBStatus || res.ModuleTCBStatus != exp.ModuleTCBStatus || res.QETCBStatus != exp.QETCBStatus ||
			len(res.AdvisoryIDs)+len(exp.AdvisoryIDs) > 0 && !slices.Equal(res.AdvisoryIDs, exp.AdvisoryIDs) {
			t.Errorf("%s/%s: v%d FMSPC %s TCB %s/%s/%s QE %s advisories %v", dir, c.Name, q.Version, res.FMSPC, res.TCBStatus,
				res.PlatformTCBStatus, res.ModuleTCBStatus, res.QETCBStatus, res.AdvisoryIDs)
		}
		if want := tagged(exp.ReportDataTag, nonce); q.ReportData != want {
			t.Errorf("%s/%s: report_data %x, want %x", dir, c.Name, q.ReportData, want)
		}
		if err := q.CheckProductionAttributes(); err != nil {
			t.Errorf("%s/%s: %v", dir, c.Name, err)
		}
		hexEq(t, dir+" td_attributes", q.TDAttributes[:], exp.TDAttributes)
		hexEq(t, dir+" xfam", q.XFAM[:], exp.XFAM)
		hexEq(t, dir+" tee_tcb_svn", q.TeeTcbSvn[:], exp.TeeTcbSvn)
		hexEq(t, dir+" mrtd", q.MRTD[:], exp.MRTD)
		for r, want := range []string{exp.RTMR0, exp.RTMR1, exp.RTMR2, exp.RTMR3} {
			hexEq(t, dir+" rtmr"+string(rune('0'+r)), q.RTMR[r][:], want)
		}
		mh := q.MeasurementsHash()
		hexEq(t, dir+" measurementsHash", mh[:], exp.MeasurementsHash)
		hexEq(t, dir+" mrowner", mrOwner(q), exp.MROwner)
		hexEq(t, dir+" mrseam", mrSEAM(q), exp.MRSEAM)
		if s := pckPPID(t, q); s != exp.PCKPPID {
			t.Errorf("%s/%s: PCK PPID %s, want %s", dir, c.Name, s, exp.PCKPPID)
		}

		evs, err := ParseEventLog([]byte(gq.EventLog))
		if err != nil {
			t.Fatal(err)
		}
		info, err := CheckRuntimeEvents(evs, q.RTMR[3])
		if err != nil {
			t.Fatalf("%s/%s: %v", dir, c.Name, err)
		}
		if info.ComposeHash != stackHash || !bytes.Equal(info.AppID[:], stackHash[:20]) ||
			info.KeyProvider != KeyProviderPayload || info.StorageFS != StorageFSPayload || !info.StorageEncrypted {
			t.Errorf("%s/%s: runtime %+v", dir, c.Name, info)
		}
		hexEq(t, dir+" app-id", info.AppID[:], exp.AppID)
		hexEq(t, dir+" instance-id", info.InstanceID[:], exp.InstanceID)
		for imr := uint32(0); imr < 3; imr++ {
			if mr, n := replayCCEL(t, evs, imr); mr != q.RTMR[imr] || n == 0 {
				t.Errorf("%s/%s: rtmr%d CCEL replay of %d entries %x, quote %x", dir, c.Name, imr, n, mr, q.RTMR[imr])
			}
		}
		if i == 0 {
			first = gcpMachineCapture{quote: q, events: evs, info: info}
			if !bytes.Equal(readMachineFile(t, dir, "quote.dat"), signed) {
				t.Errorf("%s: quote.dat is not the trimmed %s quote", dir, c.Name)
			}
			qh := sha256.Sum256(signed)
			hexEq(t, dir+" quoteHash", qh[:], exp.QuoteHash)
		} else if q.MRTD != first.quote.MRTD || q.RTMR != first.quote.RTMR || !bytes.Equal(mrOwner(q), mrOwner(first.quote)) ||
			q.ReportData == first.quote.ReportData {
			t.Errorf("%s/%s: registers differ from the first capture, or report_data does not", dir, c.Name)
		}
	}

	// GET /Info agrees with the quote and carries the exact app-compose.json bytes.
	var infoResp struct {
		TCBInfo     string `json:"tcb_info"`
		ComposeHash string `json:"compose_hash"`
		AppID       string `json:"app_id"`
		InstanceID  string `json:"instance_id"`
	}
	if err := json.Unmarshal(readMachineFile(t, dir, filepath.Join("captures", "boot1-info.json")), &infoResp); err != nil {
		t.Fatal(err)
	}
	var tcb struct {
		MRTD, RTMR0, RTMR1, RTMR2, RTMR3 string
		AppCompose                       string `json:"app_compose"`
	}
	if err := json.Unmarshal([]byte(infoResp.TCBInfo), &tcb); err != nil {
		t.Fatal(err)
	}
	if tcb.MRTD != exp.MRTD || tcb.RTMR0 != exp.RTMR0 || tcb.RTMR1 != exp.RTMR1 || tcb.RTMR2 != exp.RTMR2 || tcb.RTMR3 != exp.RTMR3 ||
		tcb.AppCompose != string(appCompose) || infoResp.ComposeHash != exp.ComposeHash || infoResp.AppID != exp.AppID ||
		infoResp.InstanceID != exp.InstanceID {
		t.Errorf("%s: /Info tcb_info, app_compose, app_id or instance_id differ from the quote", dir)
	}
	return exp, first
}

// TestRealGCPMachineTypes verifies the follow-up captures and pins what the three VMs show about where each
// register comes from. VM 1 is the spike (testdata/gcp, c3-standard-4), VM 2 a fresh c3-standard-4 and VM 3 a
// c3-standard-8; all three ran the same image and the same shared and data disk images.
//   - Per image: RTMR1 and RTMR2 are equal on all three (tools/predict_rtmr12.py computes them from disk.raw).
//   - Google firmware and host settings: MRTD, TD_ATTRIBUTES and XFAM are equal on all three, and so are the TDX
//     module's MRSEAM and TEE_TCB_SVN.
//   - Per machine type: RTMR0 is equal on the two c3-standard-4 VMs (which ran on different hosts) and differs on
//     c3-standard-8 (which ran on the same host as VM 2). Exactly the TD HOB entry and the three ACPI entries
//     change; the firmware volume, the EFI variables, the separator and the boot variables do not.
//   - Per instance: MROWNER and the instance-id event (so RTMR3) differ on every VM, although .instance_info was
//     the same; nothing else in RTMR3 changes.
func TestRealGCPMachineTypes(t *testing.T) {
	spikeExp := readGCPGolden(t)
	appCompose := readGCPFile(t, "app-compose.json")
	spikeQ, err := ParseQuote(readGCPFile(t, "quote.dat"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	spikeEvs, err := ParseEventLog(readGCPFile(t, "eventlog.json"))
	if err != nil {
		t.Fatal(err)
	}
	spikeInfo, err := CheckRuntimeEvents(spikeEvs, spikeQ.RTMR[3])
	if err != nil {
		t.Fatal(err)
	}

	type vm struct {
		name, machineType string
		c                 gcpMachineCapture
	}
	vms := []vm{{"spike (c3-standard-4 VM 1)", "c3-standard-4", gcpMachineCapture{spikeQ, spikeEvs, spikeInfo}}}
	for _, dir := range gcpMachineDirs {
		exp, c := verifyMachineDir(t, dir, appCompose)
		vms = append(vms, vm{dir, exp.MachineType, c})
	}
	if t.Failed() {
		return
	}
	base := vms[0].c

	// Per image and per platform firmware: identical on every VM and machine type.
	for _, m := range vms[1:] {
		q := m.c.quote
		if q.MRTD != base.quote.MRTD || q.RTMR[1] != base.quote.RTMR[1] || q.RTMR[2] != base.quote.RTMR[2] ||
			q.TDAttributes != base.quote.TDAttributes || q.XFAM != base.quote.XFAM || q.TeeTcbSvn != base.quote.TeeTcbSvn ||
			!bytes.Equal(mrSEAM(q), mrSEAM(base.quote)) {
			t.Errorf("%s: MRTD, RTMR1, RTMR2, TD_ATTRIBUTES, XFAM, TEE_TCB_SVN or MRSEAM differ from the spike", m.name)
		}
	}

	// Per machine type: RTMR0 and so measurementsHash.
	for _, m := range vms[1:] {
		mh := m.c.quote.MeasurementsHash()
		sameType := m.machineType == vms[0].machineType
		if (m.c.quote.RTMR[0] == base.quote.RTMR[0]) != sameType || (hex.EncodeToString(mh[:]) == spikeExp.MeasurementsHash) != sameType {
			t.Errorf("%s (%s): RTMR0 or measurementsHash equal to the spike's is %v, want %v", m.name, m.machineType,
				m.c.quote.RTMR[0] == base.quote.RTMR[0], sameType)
		}
		var b0, m0 []Event
		for _, e := range base.events {
			if e.IMR == 0 {
				b0 = append(b0, e)
			}
		}
		for _, e := range m.c.events {
			if e.IMR == 0 {
				m0 = append(m0, e)
			}
		}
		if len(b0) != len(m0) {
			t.Fatalf("%s: %d RTMR0 entries, spike %d", m.name, len(m0), len(b0))
		}
		var changed []string
		for i := range b0 {
			if b0[i].EventType != m0[i].EventType || b0[i].Event != m0[i].Event {
				t.Errorf("%s: RTMR0 entry %d is %#x %q, spike %#x %q", m.name, i, m0[i].EventType, m0[i].Event, b0[i].EventType, b0[i].Event)
			}
			if b0[i].Digest != m0[i].Digest {
				name := b0[i].Event
				if name == "" {
					name = fmt.Sprintf("%#x", b0[i].EventType)
				}
				changed = append(changed, fmt.Sprintf("%s@%02d", name, i))
			}
		}
		// Entry 0 is EV_EFI_HANDOFF_TABLES2 (0x8000000b, the TD HOB); 8-10 are the EV_PLATFORM_CONFIG_FLAGS ACPI entries.
		want := []string{}
		if !sameType {
			want = []string{"0x8000000b@00", "acpi-loader@08", "acpi-rsdp@09", "acpi-tables@10"}
		}
		if !slices.Equal(changed, want) {
			t.Errorf("%s (%s): changed RTMR0 entries %v, want %v", m.name, m.machineType, changed, want)
		}
	}

	// Per instance: MROWNER and instance-id differ on every VM; the rest of RTMR3 is the same.
	for i := range vms {
		for j := i + 1; j < len(vms); j++ {
			a, b := vms[i].c, vms[j].c
			if bytes.Equal(mrOwner(a.quote), mrOwner(b.quote)) || a.info.InstanceID == b.info.InstanceID || a.quote.RTMR[3] == b.quote.RTMR[3] {
				t.Errorf("%s and %s share MROWNER, instance-id or RTMR3", vms[i].name, vms[j].name)
			}
			if a.info.AppID != b.info.AppID || a.info.ComposeHash != b.info.ComposeHash || a.info.KeyProvider != b.info.KeyProvider {
				t.Errorf("%s and %s: app-id, compose-hash or key-provider differ", vms[i].name, vms[j].name)
			}
			var ra, rb []Event
			for _, e := range a.events {
				if e.IMR == 3 && e.Event != "instance-id" {
					ra = append(ra, e)
				}
			}
			for _, e := range b.events {
				if e.IMR == 3 && e.Event != "instance-id" {
					rb = append(rb, e)
				}
			}
			if !slices.EqualFunc(ra, rb, sameEvent) {
				t.Errorf("%s and %s: RTMR3 events other than instance-id differ", vms[i].name, vms[j].name)
			}
		}
	}

	// Hosts: the spike's two boots ran on two platforms (its stop and start moved it), and VM 2 and VM 3 on a third,
	// the same one. So RTMR0 is stable across hosts for one machine type, and its change on c3-standard-8 comes from
	// the machine type, not from the host. MROWNER stayed the same across the spike's move, so it is per instance.
	gq2, _ := readCapture(t, "boot2-getquote1")
	spikeBoot2, err := ParseQuote(mustTrim(t, gq2), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p1, p1b := pckPPID(t, spikeQ), pckPPID(t, spikeBoot2)
	p2, p3 := pckPPID(t, vms[1].c.quote), pckPPID(t, vms[2].c.quote)
	if p1 == p1b || p2 != p3 || p2 == p1 || p2 == p1b {
		t.Errorf("PCK PPIDs: spike boot 1 %s, boot 2 %s, %s %s, %s %s", p1, p1b, vms[1].name, p2, vms[2].name, p3)
	}
	if !bytes.Equal(mrOwner(spikeBoot2), mrOwner(spikeQ)) || spikeBoot2.RTMR[0] != spikeQ.RTMR[0] {
		t.Error("spike boot 2: MROWNER or RTMR0 differ from boot 1")
	}
}

// mustTrim returns the signed bytes of a captured GetQuote answer.
func mustTrim(t *testing.T, gq getQuoteResponse) []byte {
	t.Helper()
	padded, err := hex.DecodeString(gq.Quote)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := TrimQuote(padded)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
