package keybroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Denial reason codes (INTERFACES.md section 9). A release that fails a check answers 403 with one of these.
const (
	ReasonBadNonce             = "bad_nonce"
	ReasonQuoteInvalid         = "quote_invalid"
	ReasonTCBStatus            = "tcb_status"
	ReasonReportDataMismatch   = "report_data_mismatch"
	ReasonImageNotApproved     = "image_not_approved"
	ReasonImageDebug           = "image_debug"
	ReasonMeasurementsMismatch = "measurements_mismatch"
	ReasonRTMR3Replay          = "rtmr3_replay"
	ReasonComposeMismatch      = "compose_mismatch"
	ReasonBundleHashMismatch   = "bundle_hash_mismatch"
	ReasonCustomerMismatch     = "customer_mismatch"
	ReasonStackNotApproved     = "stack_not_approved"
)

// DenialReasons lists the INTERFACES.md section 9 codes in check order.
var DenialReasons = []string{
	ReasonBadNonce, ReasonQuoteInvalid, ReasonTCBStatus, ReasonReportDataMismatch, ReasonImageNotApproved,
	ReasonImageDebug, ReasonMeasurementsMismatch, ReasonRTMR3Replay, ReasonComposeMismatch, ReasonBundleHashMismatch,
	ReasonCustomerMismatch, ReasonStackNotApproved,
}

// Codes that are not denials of an attested stack. bad_request answers 400; the others answer 503 so the agent
// retries (the request may succeed once the dependency is back or the customer stored the secret).
const (
	ReasonBadRequest    = "bad_request"
	ReasonUnavailable   = "unavailable"
	ReasonSecretMissing = "secret_missing"
	ReasonSecretInvalid = "secret_invalid"
	ReasonLogFailed     = "decision_log_unavailable"
)

// Decision values.
const (
	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
	DecisionError   = "error"
)

// Check names, in pipeline order.
const (
	CheckRequest          = "request"
	CheckNonce            = "nonce"
	CheckQuote            = "quote"
	CheckReportData       = "report_data"
	CheckImage            = "image"
	CheckRTMR3            = "rtmr3"
	CheckComposeHash      = "compose_hash"
	CheckStackRecompute   = "stack_recompute"
	CheckCustomer         = "customer"
	CheckStackApproved    = "stack_approved"
	CheckApprovalReleases = "approval_releases"
	CheckSecrets          = "secrets"
	CheckKeys             = "keys"
	CheckSeal             = "seal"
)

// Check is one step of a release decision.
type Check struct {
	Name   string         `json:"name"`
	OK     bool           `json:"ok"`
	Reason string         `json:"reason,omitempty"`
	Detail string         `json:"detail,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}

// Hashes are the identifiers a decision is about. Every value is public (no secret ever appears in a decision).
type Hashes struct {
	Nonce            string   `json:"nonce,omitempty"`
	EphemeralPub     string   `json:"ephemeralPub,omitempty"`
	QuoteHash        string   `json:"quoteHash,omitempty"`
	EventLogHash     string   `json:"eventLogHash,omitempty"`
	ImageID          string   `json:"imageId,omitempty"`
	MeasurementsHash string   `json:"measurementsHash,omitempty"`
	RTMR3            string   `json:"rtmr3,omitempty"`
	ComposeHash      string   `json:"composeHash,omitempty"`
	StackHash        string   `json:"stackHash,omitempty"`
	ConfigHash       string   `json:"configHash,omitempty"`
	DeploymentID     string   `json:"deploymentId,omitempty"`
	Customer         string   `json:"customer,omitempty"`
	ReleaseIDs       []string `json:"releaseIds,omitempty"`
	BlockNumber      uint64   `json:"blockNumber,omitempty"`
}

// Decision is one structured decision log entry.
type Decision struct {
	Time       time.Time `json:"time"`
	RequestID  string    `json:"requestId"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	HTTPStatus int       `json:"httpStatus"`
	Simulated  bool      `json:"simulated"`
	Remote     string    `json:"remote,omitempty"`
	Hashes     Hashes    `json:"hashes"`
	Checks     []Check   `json:"checks"`
	// Released lists "<owner>/<NAME>" of every released secret (names only), plus diskKey and signerSeed.
	Released   []string `json:"released,omitempty"`
	DurationMS int64    `json:"durationMs"`
}

// Severity maps a decision to a Cloud Logging severity.
func (d *Decision) Severity() string {
	switch d.Decision {
	case DecisionAllowed:
		return "NOTICE"
	case DecisionDenied:
		return "WARNING"
	default:
		return "ERROR"
	}
}

// Message is a one-line summary of the decision.
func (d *Decision) Message() string {
	if d.Decision == DecisionAllowed {
		return fmt.Sprintf("key release allowed for stack %s", d.Hashes.StackHash)
	}
	return fmt.Sprintf("key release %s: %s", d.Decision, d.Reason)
}

// DecisionLog persists decisions. Cloud Logging in production (key-broker/gcp), JSON lines locally. Write must be
// safe for concurrent use. A release is only answered with secrets after Write of its decision returned nil.
type DecisionLog interface {
	Write(ctx context.Context, d *Decision) error
}

// JSONLinesLog writes one JSON object per line. It is the local fake of Cloud Logging and the format tests read.
type JSONLinesLog struct {
	mu sync.Mutex
	w  io.Writer
	f  *os.File
}

// NewJSONLinesLog writes decisions to w.
func NewJSONLinesLog(w io.Writer) *JSONLinesLog { return &JSONLinesLog{w: w} }

// OpenJSONLinesLog appends decisions to the file at path (created with mode 0600).
func OpenJSONLinesLog(path string) (*JSONLinesLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &JSONLinesLog{w: f, f: f}, nil
}

// Write implements DecisionLog.
func (l *JSONLinesLog) Write(_ context.Context, d *Decision) error {
	line, err := json.Marshal(struct {
		Severity string `json:"severity"`
		Message  string `json:"message"`
		*Decision
	}{d.Severity(), d.Message(), d})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(line); err != nil {
		return err
	}
	if l.f != nil {
		return l.f.Sync()
	}
	return nil
}

// Close closes the file opened by OpenJSONLinesLog.
func (l *JSONLinesLog) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// MemoryLog keeps decisions in memory (tests).
type MemoryLog struct {
	mu  sync.Mutex
	all []*Decision
	// Fail makes Write return this error.
	Fail error
}

// Write implements DecisionLog.
func (m *MemoryLog) Write(_ context.Context, d *Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	cp := *d
	m.all = append(m.all, &cp)
	return nil
}

// All returns the decisions written so far.
func (m *MemoryLog) All() []*Decision {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*Decision(nil), m.all...)
}

// Last returns the latest decision, or nil.
func (m *MemoryLog) Last() *Decision {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.all) == 0 {
		return nil
	}
	return m.all[len(m.all)-1]
}

// MultiLog writes to every log in order and returns the first error.
type MultiLog []DecisionLog

// Write implements DecisionLog.
func (m MultiLog) Write(ctx context.Context, d *Decision) error {
	var errs []error
	for _, l := range m {
		if err := l.Write(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
