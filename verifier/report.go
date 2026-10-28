package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"
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
	CheckExpectedApps      = "expected_apps"
	CheckLiveFetch         = "live_fetch"
	CheckTLSBinding        = "tls_binding"
)

// Modes of a report.
const (
	ModeEvidence = "evidence"
	ModeLive     = "live"
	// ModeLiveSubmitted is a live attestation fetched by the caller (VerifyLiveSubmission).
	ModeLiveSubmitted = "live_submitted"
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
// about real hardware, and it is OK only when the verification opted in (Options.AcceptSimulated).
type Report struct {
	OK           bool   `json:"ok"`
	Simulated    bool   `json:"simulated"`
	Mode         string `json:"mode"`
	DeploymentID string `json:"deploymentId,omitempty"`
	StackHash    string `json:"stackHash,omitempty"`
	RecordDigest string `json:"recordDigest,omitempty"`
	// BlockNumber is the block every chain read of this verification ran against (0 when not pinned).
	BlockNumber uint64 `json:"blockNumber,omitempty"`
	VerifiedAt  int64  `json:"verifiedAt"`
	// Config summarizes what the customer approved in the public config beyond its hash: debug logging, the
	// endpoints the stack trusts and the egress it may use (nil when the config did not parse).
	Config *ConfigSummary `json:"config,omitempty"`
	Checks []Check        `json:"checks"`

	// simulatedAccepted records that the quote check accepted a simulated quote under Options.AcceptSimulated.
	simulatedAccepted bool
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

// finish computes OK. A simulated report is never OK unless the quote check accepted it on the caller's opt-in.
func (r *Report) finish() *Report {
	r.OK = len(r.Checks) > 0 && (!r.Simulated || r.simulatedAccepted)
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

// WriteText writes a human-readable report. Details embed values from the bundle, the /attest response and the
// chain (app ids, versions, error text), so every string is made printable first: a crafted value cannot move the
// cursor, overwrite FAIL lines or reorder text with control or bidi characters.
func (r *Report) WriteText(w io.Writer) error {
	result := "FAIL"
	if r.OK {
		result = "PASS"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Sealed verification (%s): %s\n", printable(r.Mode), result)
	if r.DeploymentID != "" {
		fmt.Fprintf(&b, "  deployment  %s\n", printable(r.DeploymentID))
	}
	if r.StackHash != "" {
		fmt.Fprintf(&b, "  stack       %s\n", printable(r.StackHash))
	}
	if r.BlockNumber != 0 {
		fmt.Fprintf(&b, "  block       %d\n", r.BlockNumber)
	}
	fmt.Fprintf(&b, "  verified at %s\n", time.Unix(r.VerifiedAt, 0).UTC().Format(time.RFC3339))
	if r.Simulated {
		b.WriteString("  WARNING: the quote comes from the dev simulator. This is not a TDX attestation.\n")
	}
	if c := r.Config; c != nil {
		if c.Endpoints.KeyBroker != "" {
			fmt.Fprintf(&b, "  key broker  %s\n", printable(c.Endpoints.KeyBroker))
		}
		if c.Endpoints.Relay != "" {
			fmt.Fprintf(&b, "  relay       %s\n", printable(c.Endpoints.Relay))
		}
		for _, app := range sortedKeys(c.EgressAdditions) {
			fmt.Fprintf(&b, "  egress      %s may also reach %s\n", printable(app), printable(strings.Join(c.EgressAdditions[app], ", ")))
		}
		if len(c.AllowedVpcRanges) > 0 {
			fmt.Fprintf(&b, "  vpc ranges  %s\n", printable(strings.Join(c.AllowedVpcRanges, ", ")))
		}
		if c.Debug {
			b.WriteString("  NOTE: config.debug is on: containers keep their logs on the VM (local logging driver).\n")
		}
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
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", mark, printable(c.Name), printable(c.Detail))
	}
	tw.Flush()
	fmt.Fprintf(&b, "\n%d of %d checks passed.\n", passed, len(r.Checks))
	_, err := io.WriteString(w, b.String())
	return err
}

// printable escapes control characters, format characters (bidi overrides, zero-width), invalid UTF-8 and every
// other non-graphic rune with Go escapes; graphic runes and spaces pass unchanged.
func printable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsGraphic(r):
			b.WriteRune(r)
		default:
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}

// Text returns WriteText's output as a string.
func (r *Report) Text() string {
	var b strings.Builder
	_ = r.WriteText(&b)
	return b.String()
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
