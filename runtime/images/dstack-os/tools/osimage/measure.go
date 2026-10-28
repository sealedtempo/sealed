// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/pcs"

	"github.com/sealed-dev/sealed/verifier/attest"
)

const measurementSchema = "sealed-os-measurement/v1"

// TCG event types used below.
const (
	evNoAction                   = 0x3
	evEFIBootServicesApplication = 0x80000003
)

// measurement is the record of one measurement boot (one machine type, one VM).
type measurement struct {
	Schema           string `json:"schema"`
	Image            string `json:"image"`
	Variant          string `json:"variant"`
	OSImageHash      string `json:"osImageHash"`
	MachineType      string `json:"machineType"`
	Zone             string `json:"zone,omitempty"`
	Boot             int    `json:"boot"`
	MeasuredAt       string `json:"measuredAt"`
	MRTD             string `json:"mrtd"`
	RTMR0            string `json:"rtmr0"`
	RTMR1            string `json:"rtmr1"`
	RTMR2            string `json:"rtmr2"`
	RTMR3            string `json:"rtmr3"`
	MeasurementsHash string `json:"measurementsHash"`
	ReportData       string `json:"reportData"`
	TDAttributes     string `json:"tdAttributes"`
	XFAM             string `json:"xfam"`
	TeeTCBSVN        string `json:"teeTcbSvn"`
	Quote            struct {
		SHA256      string   `json:"sha256"`
		Verified    bool     `json:"verified"`
		TCBStatus   string   `json:"tcbStatus,omitempty"`
		QETCBStatus string   `json:"qeTcbStatus,omitempty"`
		FMSPC       string   `json:"fmspc,omitempty"`
		AdvisoryIDs []string `json:"advisoryIds,omitempty"`
	} `json:"quote"`
	EventLog struct {
		Events int `json:"events"`
		// ReplayMatches reports, per register, whether replaying the firmware event log reproduces the quote.
		ReplayMatches map[string]bool `json:"replayMatches"`
		// RTMR1Applications are the digests of EV_EFI_BOOT_SERVICES_APPLICATION events (boot applications).
		RTMR1Applications []string `json:"rtmr1Applications"`
		// UKIInRTMR1 reports whether the UKI's SHA-384 Authenticode digest from the build is among them, which ties
		// RTMR1 to the published boot disk beyond trust on first use.
		UKIInRTMR1 bool `json:"ukiInRtmr1"`
	} `json:"eventLog"`
	Trust string `json:"trust"`
}

// ccEvent is one entry of the event_log the guest agent returns (imr 0-2 are RTMR0-2).
type ccEvent struct {
	IMR          uint32 `json:"imr"`
	EventType    uint32 `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
}

var serialLine = regexp.MustCompile(`SEALED-MEASURE (BEGIN v1|END ([0-9a-f]{64}) ([0-9a-f]{64})|FAIL .*|([QE]) ([0-9]{5}) ([0-9A-Za-z+/=]+))\s*$`)

// parseSerial extracts the quote (hex) and the event log JSON of the last complete block a measurement boot printed.
func parseSerial(r io.Reader) (quoteHex string, events []byte, err error) {
	type block struct {
		chunks map[string]map[int]string
		end    []string
	}
	var cur *block
	var done *block
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		m := serialLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		switch {
		case m[1] == "BEGIN v1":
			cur = &block{chunks: map[string]map[int]string{"Q": {}, "E": {}}}
		case strings.HasPrefix(m[1], "FAIL"):
			return "", nil, fmt.Errorf("measurement boot failed: %s", m[1])
		case strings.HasPrefix(m[1], "END"):
			if cur != nil {
				cur.end = []string{m[2], m[3]}
				done, cur = cur, nil
			}
		case cur != nil:
			i, _ := strconv.Atoi(m[5])
			cur.chunks[m[4]][i] = m[6]
		}
	}
	if err := sc.Err(); err != nil {
		return "", nil, err
	}
	if done == nil {
		return "", nil, errors.New("no complete SEALED-MEASURE block in the serial output")
	}
	join := func(tag string) (string, error) {
		parts := done.chunks[tag]
		var b strings.Builder
		for i := 0; i < len(parts); i++ {
			p, ok := parts[i]
			if !ok {
				return "", fmt.Errorf("serial output is missing %s chunk %d", tag, i)
			}
			b.WriteString(p)
		}
		return b.String(), nil
	}
	if quoteHex, err = join("Q"); err != nil {
		return "", nil, err
	}
	ev64, err := join("E")
	if err != nil {
		return "", nil, err
	}
	if sum := sha256.Sum256([]byte(quoteHex)); hex.EncodeToString(sum[:]) != done.end[0] {
		return "", nil, errors.New("quote checksum mismatch: the serial output was corrupted")
	}
	if sum := sha256.Sum256([]byte(ev64)); hex.EncodeToString(sum[:]) != done.end[1] {
		return "", nil, errors.New("event log checksum mismatch: the serial output was corrupted")
	}
	events, err = base64.StdEncoding.DecodeString(ev64)
	if err != nil {
		return "", nil, fmt.Errorf("event log: %w", err)
	}
	return quoteHex, events, nil
}

// replayRTMRs folds the event log into RTMR0-2: RTMR = SHA384(RTMR || digest) from 48 zero bytes, skipping
// EV_NO_ACTION entries, which firmware logs but never extends.
func replayRTMRs(events []ccEvent) ([3][48]byte, error) {
	var mrs [3][48]byte
	for i, e := range events {
		if e.IMR > 2 || e.EventType == evNoAction {
			continue
		}
		d, err := hex.DecodeString(e.Digest)
		if err != nil || len(d) != 48 {
			return mrs, fmt.Errorf("event %d: digest is not 48 bytes of hex", i)
		}
		h := sha512.New384()
		h.Write(mrs[e.IMR][:])
		h.Write(d)
		copy(mrs[e.IMR][:], h.Sum(nil))
	}
	return mrs, nil
}

func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// measureOptions control quote verification.
type measureOptions struct {
	verify        bool
	collateralDir string
	offline       bool
	at            time.Time
}

type offlineGetter struct{}

func (offlineGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("offline: collateral not in the cache directory")
}

// measurementPolicy accepts every TCB status but Revoked. The platform TCB is not a property of the image, so a
// measurement is recorded whatever it is (and the status is recorded with it); the key broker applies its own
// policy at release time.
func measurementPolicy() attest.TCBPolicy {
	return attest.TCBPolicy{AllowedStatuses: []string{
		string(pcs.TcbComponentStatusUpToDate),
		string(pcs.TcbComponentStatusSwHardeningNeeded),
		string(pcs.TcbComponentStatusConfigurationNeeded),
		string(pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded),
		string(pcs.TcbComponentStatusOutOfDate),
		string(pcs.TcbComponentStatusOutOfDateConfigurationNeeded),
		string(pcs.TcbComponentStatusRelaunchAdvisedConfigurationNeeded),
	}}
}

// measure turns a measurement boot's quote and event log into a measurement record. It fails when the quote does
// not verify (unless verification is off), when report_data is not the nonce the boot was given, or when the TD
// attributes are not those of a production TD.
func measure(ctx context.Context, rawQuote, events, reportData []byte, id *identity, o measureOptions) (*measurement, error) {
	raw, err := attest.TrimQuote(rawQuote)
	if err != nil {
		return nil, err
	}
	m := &measurement{Schema: measurementSchema, Trust: "tofu"}
	sum := sha256.Sum256(raw)
	m.Quote.SHA256 = hex.EncodeToString(sum[:])
	var q *attest.Quote
	if o.verify {
		gopts := attest.CacheOptions{Dir: o.collateralDir}
		if o.offline {
			gopts.Inner = offlineGetter{}
			gopts.TTL = 100 * 365 * 24 * time.Hour
		}
		vopts := attest.VerifierOptions{TCBPolicy: measurementPolicy()}
		if !o.at.IsZero() {
			at := o.at
			gopts.Now = func() time.Time { return at }
			vopts.Now = gopts.Now
		}
		g, err := attest.NewCachingGetter(gopts)
		if err != nil {
			return nil, err
		}
		vopts.Getter = g
		v, err := attest.NewVerifier(vopts)
		if err != nil {
			return nil, err
		}
		res, err := v.VerifyQuote(ctx, raw)
		if err != nil {
			return nil, fmt.Errorf("quote does not verify: %w", err)
		}
		q = res.Quote
		m.Quote.Verified = true
		m.Quote.TCBStatus, m.Quote.QETCBStatus, m.Quote.FMSPC, m.Quote.AdvisoryIDs = res.TCBStatus, res.QETCBStatus, res.FMSPC, res.AdvisoryIDs
	} else {
		if q, err = attest.ParseQuote(raw, attest.ParseOptions{}); err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(q.ReportData[:], reportData) {
		return nil, fmt.Errorf("report_data %x is not the nonce of this measurement boot", q.ReportData[:])
	}
	if err := q.CheckProductionAttributes(); err != nil {
		return nil, err
	}
	m.MRTD, m.RTMR0, m.RTMR1, m.RTMR2, m.RTMR3 = hex0x(q.MRTD[:]), hex0x(q.RTMR[0][:]), hex0x(q.RTMR[1][:]), hex0x(q.RTMR[2][:]), hex0x(q.RTMR[3][:])
	mh := q.MeasurementsHash()
	m.MeasurementsHash = hex0x(mh[:])
	m.ReportData = hex0x(q.ReportData[:])
	m.TDAttributes, m.XFAM, m.TeeTCBSVN = hex0x(q.TDAttributes[:]), hex0x(q.XFAM[:]), hex0x(q.TeeTcbSvn[:])

	var log []ccEvent
	if err := json.Unmarshal(events, &log); err != nil {
		return nil, fmt.Errorf("event log: %w", err)
	}
	m.EventLog.Events = len(log)
	replayed, err := replayRTMRs(log)
	if err != nil {
		return nil, err
	}
	m.EventLog.ReplayMatches = map[string]bool{}
	for i := 0; i < 3; i++ {
		m.EventLog.ReplayMatches[fmt.Sprintf("rtmr%d", i)] = bytes.Equal(replayed[i][:], q.RTMR[i][:])
	}
	m.EventLog.RTMR1Applications = []string{}
	for _, e := range log {
		if e.IMR == 1 && e.EventType == evEFIBootServicesApplication {
			d := strings.ToLower(e.Digest)
			m.EventLog.RTMR1Applications = append(m.EventLog.RTMR1Applications, d)
			if id != nil && d == strings.ToLower(id.UKI.AuthenticodeSHA384) {
				m.EventLog.UKIInRTMR1 = true
			}
		}
	}
	if id != nil {
		m.Image, m.Variant, m.OSImageHash = id.Name, id.Variant, id.OSImageHash
	}
	return m, nil
}

func cmdMeasure(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("measure", flag.ContinueOnError)
	serial := fs.String("serial", "", "serial console output of the measurement boot")
	rd := fs.String("report-data", "", "64-byte hex nonce the boot quoted over")
	idPath := fs.String("identity", "", "image-identity.json of the booted image")
	machineType := fs.String("machine-type", "", "GCE machine type of the boot")
	zone := fs.String("zone", "", "GCE zone of the boot")
	boot := fs.Int("boot", 1, "boot number for this machine type")
	noVerify := fs.Bool("no-verify", false, "parse the quote without verifying it against Intel collateral")
	collateral := fs.String("collateral-dir", "", "directory caching the Intel PCS collateral used for verification")
	offline := fs.Bool("offline", false, "verify only with collateral already in -collateral-dir")
	atFlag := fs.String("at", "", "verification time (RFC 3339 or Unix seconds); default now")
	saveDir := fs.String("save", "", "directory to save quote.bin and eventlog.json in")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serial == "" || *machineType == "" {
		return errors.New("-serial and -machine-type are required")
	}
	reportData, err := parseReportData(*rd)
	if err != nil {
		return err
	}
	var id *identity
	if *idPath != "" {
		if id, err = readIdentity(*idPath); err != nil {
			return err
		}
	}
	o := measureOptions{verify: !*noVerify, collateralDir: *collateral, offline: *offline}
	if *atFlag != "" {
		if o.at, err = parseTime(*atFlag); err != nil {
			return err
		}
	}
	f, err := os.Open(*serial)
	if err != nil {
		return err
	}
	defer f.Close()
	quoteHex, events, err := parseSerial(f)
	if err != nil {
		return err
	}
	rawQuote, err := hex.DecodeString(quoteHex)
	if err != nil {
		return fmt.Errorf("quote: %w", err)
	}
	if *saveDir != "" {
		if err := os.WriteFile(filepath.Join(*saveDir, "quote.bin"), rawQuote, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*saveDir, "eventlog.json"), events, 0o644); err != nil {
			return err
		}
	}
	m, err := measure(context.Background(), rawQuote, events, reportData, id, o)
	if err != nil {
		return err
	}
	m.MachineType, m.Zone, m.Boot = *machineType, *zone, *boot
	m.MeasuredAt = time.Now().UTC().Format(time.RFC3339)
	if !o.at.IsZero() {
		m.MeasuredAt = o.at.UTC().Format(time.RFC3339)
	}
	for reg, ok := range m.EventLog.ReplayMatches {
		if !ok {
			fmt.Fprintf(stderr, "osimage: warning: replaying the event log does not reproduce %s\n", reg)
		}
	}
	if id != nil && !m.EventLog.UKIInRTMR1 {
		fmt.Fprintf(stderr, "osimage: warning: the UKI SHA-384 Authenticode digest %s is not among the RTMR1 boot applications %v\n",
			id.UKI.AuthenticodeSHA384, m.EventLog.RTMR1Applications)
	}
	return writeJSON(stdout, m)
}

func parseTime(s string) (time.Time, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Parse(time.RFC3339, s)
}
