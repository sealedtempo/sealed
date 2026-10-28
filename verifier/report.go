package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// Check names. Each one is a stable identifier that clients and tests rely on.
const (
	CheckBundle            = "bundle"
	CheckChain             = "chain"
	CheckQuoteHash         = "quote_hash"
	CheckQuote             = "quote"
	CheckTDAttributes      = "td_attributes"
	CheckImageMeasurements = "image_measurements"
	CheckImageApproved     = "image_approved"
	CheckEventLogHash      = "event_log_hash"
	CheckRTMR3             = "rtmr3"
	CheckComposeHash       = "compose_hash"
	CheckConfigHash        = "config_hash"
	CheckConfigBinding     = "config_binding"
	CheckDeploymentID      = "deployment_id"
	CheckReportData        = "report_data"
	CheckFreshness         = "freshness"
	CheckReleasesActive    = "releases_active"
	CheckStackRecompute    = "stack_recompute"
	CheckStackApproved     = "stack_approved"
	CheckApprovalReleases  = "approval_releases"
	CheckOnchainRecord     = "onchain_record"
	CheckExpectedCustomer  = "expected_customer"
	CheckLiveFetch         = "live_fetch"
	CheckTLSBinding        = "tls_binding"
)

// Modes of a report.
const (
	ModeEvidence = "evidence"
	ModeLive     = "live"
)

// Check is one verification step.
type Check struct {
	Name   string         `json:"name"`
	OK     bool           `json:"ok"`
	Detail string         `json:"detail"`
	Data   map[string]any `json:"data,omitempty"`
}

// Report is the outcome of a verification. OK is true only when there is at least one check and every check
// passed. Simulated is true whenever the quote came from the dev simulator; such a report never proves anything
// about real hardware.
type Report struct {
	OK           bool    `json:"ok"`
	Simulated    bool    `json:"simulated"`
	Mode         string  `json:"mode"`
	DeploymentID string  `json:"deploymentId,omitempty"`
	StackHash    string  `json:"stackHash,omitempty"`
	RecordDigest string  `json:"recordDigest,omitempty"`
	VerifiedAt   int64   `json:"verifiedAt"`
	Checks       []Check `json:"checks"`
}

func newReport(mode string, now time.Time) *Report {
	return &Report{Mode: mode, VerifiedAt: now.Unix()}
}

func (r *Report) add(name string, ok bool, detail string, data map[string]any) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail, Data: data})
}

func (r *Report) pass(name, detail string, data map[string]any) { r.add(name, true, detail, data) }

func (r *Report) fail(name, detail string, data map[string]any) { r.add(name, false, detail, data) }

func (r *Report) failf(name, format string, args ...any) {
	r.fail(name, fmt.Sprintf(format, args...), nil)
}

// finish computes OK.
func (r *Report) finish() *Report {
	r.OK = len(r.Checks) > 0
	for _, c := range r.Checks {
		if !c.OK {
			r.OK = false
		}
	}
	return r
}

// Check returns the named check, or nil.
func (r *Report) Check(name string) *Check {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			return &r.Checks[i]
		}
	}
	return nil
}

// Failed returns the names of the failed checks.
func (r *Report) Failed() []string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name)
		}
	}
	return out
}

// JSON returns the report as indented JSON.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// WriteText writes a human-readable report.
func (r *Report) WriteText(w io.Writer) error {
	result := "FAIL"
	if r.OK {
		result = "PASS"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Sealed verification (%s): %s\n", r.Mode, result)
	if r.DeploymentID != "" {
		fmt.Fprintf(&b, "  deployment  %s\n", r.DeploymentID)
	}
	if r.StackHash != "" {
		fmt.Fprintf(&b, "  stack       %s\n", r.StackHash)
	}
	fmt.Fprintf(&b, "  verified at %s\n", time.Unix(r.VerifiedAt, 0).UTC().Format(time.RFC3339))
	if r.Simulated {
		b.WriteString("  WARNING: the quote comes from the dev simulator. This is not a TDX attestation.\n")
	}
	b.WriteString("\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	passed := 0
	for _, c := range r.Checks {
		mark := "FAIL"
		if c.OK {
			mark = "ok"
			passed++
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", mark, c.Name, c.Detail)
	}
	tw.Flush()
	fmt.Fprintf(&b, "\n%d of %d checks passed.\n", passed, len(r.Checks))
	_, err := io.WriteString(w, b.String())
	return err
}

// Text returns WriteText's output as a string.
func (r *Report) Text() string {
	var b strings.Builder
	_ = r.WriteText(&b)
	return b.String()
}
