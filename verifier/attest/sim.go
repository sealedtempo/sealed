package attest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sealedtempo/sealed/runtime/composer/cjson"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
)

// Simulated quote format (INTERFACES.md section 15): ASCII "SEALEDSIM1" followed by CJSON of simQuoteBody.
const (
	SimQuotePrefix = "SEALEDSIM1"
	SimQuoteSchema = "sealed-sim-quote/v1"
)

// Fixed simulator measurements. Registered as images sealed-sim and sealed-sim-debug on local chains only.
var (
	SimMRTD      = fill(0x11)
	SimMRTDDebug = fill(0x55)
	SimRTMR0     = fill(0x22)
	SimRTMR1     = fill(0x33)
	SimRTMR2     = fill(0x44)
)

func fill(b byte) Measurement {
	var m Measurement
	for i := range m {
		m[i] = b
	}
	return m
}

type simQuoteBody struct {
	Debug      bool   `json:"debug"`
	MRTD       string `json:"mrtd"`
	ReportData string `json:"reportData"`
	RTMR0      string `json:"rtmr0"`
	RTMR1      string `json:"rtmr1"`
	RTMR2      string `json:"rtmr2"`
	RTMR3      string `json:"rtmr3"`
	Schema     string `json:"schema"`
}

// IsSimulatedQuote reports whether raw uses the dev simulator format.
func IsSimulatedQuote(raw []byte) bool { return bytes.HasPrefix(raw, []byte(SimQuotePrefix)) }

func parseSimQuote(raw []byte) (*Quote, error) {
	doc := raw[len(SimQuotePrefix):]
	canon, err := cjson.Canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: simulated quote: %v", ErrQuoteInvalid, err)
	}
	if !bytes.Equal(canon, doc) {
		return nil, fmt.Errorf("%w: simulated quote body is not canonical JSON", ErrQuoteInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var body simQuoteBody
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("%w: simulated quote: %v", ErrQuoteInvalid, err)
	}
	if body.Schema != SimQuoteSchema {
		return nil, fmt.Errorf("%w: simulated quote schema %q", ErrQuoteInvalid, body.Schema)
	}
	q := &Quote{Raw: bytes.Clone(raw), Simulated: true}
	fields := []struct {
		name string
		src  string
		dst  []byte
	}{
		{"mrtd", body.MRTD, q.MRTD[:]},
		{"rtmr0", body.RTMR0, q.RTMR[0][:]},
		{"rtmr1", body.RTMR1, q.RTMR[1][:]},
		{"rtmr2", body.RTMR2, q.RTMR[2][:]},
		{"rtmr3", body.RTMR3, q.RTMR[3][:]},
		{"reportData", body.ReportData, q.ReportData[:]},
	}
	for _, f := range fields {
		b, err := hexb.Decode(f.src, len(f.dst))
		if err != nil {
			return nil, fmt.Errorf("%w: simulated quote %s: %v", ErrQuoteInvalid, f.name, err)
		}
		copy(f.dst, b)
	}
	// The format carries only the debug flag; the attributes are those of a production Linux TD (plus DEBUG).
	attrs := tdAttrSeptVEDisable
	if body.Debug {
		attrs |= tdAttrDebug
	}
	binary.LittleEndian.PutUint64(q.TDAttributes[:], attrs)
	return q, nil
}

// SimQuoteParams describe a simulated quote. Measurements default to the fixed simulator values.
type SimQuoteParams struct {
	Debug      bool
	RTMR3      Measurement
	ReportData ReportData
	// Overrides for tamper tests; nil keeps the fixed values.
	MRTD *Measurement
}

// NewSimQuote returns simulated quote bytes exactly as the dev simulator emits them.
func NewSimQuote(p SimQuoteParams) []byte {
	mrtd := SimMRTD
	if p.Debug {
		mrtd = SimMRTDDebug
	}
	if p.MRTD != nil {
		mrtd = *p.MRTD
	}
	body := simQuoteBody{
		Debug:      p.Debug,
		MRTD:       hex.EncodeToString(mrtd[:]),
		ReportData: hex.EncodeToString(p.ReportData[:]),
		RTMR0:      hex.EncodeToString(SimRTMR0[:]),
		RTMR1:      hex.EncodeToString(SimRTMR1[:]),
		RTMR2:      hex.EncodeToString(SimRTMR2[:]),
		RTMR3:      hex.EncodeToString(p.RTMR3[:]),
		Schema:     SimQuoteSchema,
	}
	doc, err := cjson.Marshal(body)
	if err != nil {
		panic(err) // fixed struct of strings and a bool; cannot fail
	}
	return append([]byte(SimQuotePrefix), doc...)
}

// SimMeasurementsHash returns the measurementsHash of the sealed-sim (or sealed-sim-debug) image.
func SimMeasurementsHash(debug bool) [32]byte {
	mrtd := SimMRTD
	if debug {
		mrtd = SimMRTDDebug
	}
	return MeasurementsHash(mrtd, SimRTMR0, SimRTMR1, SimRTMR2)
}
