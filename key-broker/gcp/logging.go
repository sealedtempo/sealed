package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
)

// DefaultLoggingEndpoint is the Cloud Logging REST API.
const DefaultLoggingEndpoint = "https://logging.googleapis.com"

// DefaultDecisionLogID is the log every release decision is written to.
const DefaultDecisionLogID = "sealed-key-broker-decisions"

var logIDRe = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,512}$`)

// MonitoredResource is the Cloud Logging resource of the entries.
type MonitoredResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

// CloudRunResource describes this Cloud Run revision from the variables Cloud Run sets (K_SERVICE, K_REVISION,
// K_CONFIGURATION), or the global resource elsewhere.
func CloudRunResource(project, region string, getenv func(string) string) MonitoredResource {
	if svc := getenv("K_SERVICE"); svc != "" {
		return MonitoredResource{Type: "cloud_run_revision", Labels: map[string]string{
			"project_id": project, "service_name": svc, "revision_name": getenv("K_REVISION"),
			"configuration_name": getenv("K_CONFIGURATION"), "location": region,
		}}
	}
	return MonitoredResource{Type: "global", Labels: map[string]string{"project_id": project}}
}

// LoggingSink writes decisions to the customer's Cloud Logging with entries.write. The broker's service account
// has roles/logging.logWriter.
type LoggingSink struct {
	Project  string
	LogID    string // empty means DefaultDecisionLogID
	Resource MonitoredResource
	Endpoint string // empty means DefaultLoggingEndpoint
	Tokens   TokenSource
	Client   *http.Client
}

// NewLoggingSink validates the project and log id.
func NewLoggingSink(project, logID string, res MonitoredResource, tokens TokenSource) (*LoggingSink, error) {
	if !projectRe.MatchString(project) {
		return nil, fmt.Errorf("gcp: %q is not a project id", project)
	}
	if logID == "" {
		logID = DefaultDecisionLogID
	}
	if !logIDRe.MatchString(logID) {
		return nil, fmt.Errorf("gcp: %q is not a log id", logID)
	}
	if tokens == nil {
		return nil, errors.New("gcp: no token source")
	}
	return &LoggingSink{Project: project, LogID: logID, Resource: res, Tokens: tokens}, nil
}

// Write implements keybroker.DecisionLog. The entry's jsonPayload is the decision; labels carry decision and reason
// so they can be filtered and alerted on.
func (l *LoggingSink) Write(ctx context.Context, d *keybroker.Decision) error {
	e, _, err := l.entry(d)
	if err != nil {
		return err
	}
	return l.post(ctx, []map[string]any{e}, false)
}

// MaxBatchBytes bounds the entries of one entries:write call. Cloud Logging accepts requests of up to 10 MB.
const MaxBatchBytes = 4 << 20

// WriteBatch implements keybroker.BatchLog: the decisions go out in as few entries:write calls as fit in
// MaxBatchBytes each (kb-6). partialSuccess is set, so one refused entry does not drop the others; the insertId (the
// request id) lets Cloud Logging drop the duplicates of a retried call.
func (l *LoggingSink) WriteBatch(ctx context.Context, ds []*keybroker.Decision) error {
	var errs []error
	var entries []map[string]any
	size := 0
	flush := func() {
		if len(entries) == 0 {
			return
		}
		if err := l.post(ctx, entries, true); err != nil {
			errs = append(errs, err)
		}
		entries, size = nil, 0
	}
	for _, d := range ds {
		e, n, err := l.entry(d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(entries) > 0 && size+n > MaxBatchBytes {
			flush()
		}
		entries = append(entries, e)
		size += n
	}
	flush()
	return errors.Join(errs...)
}

// entry is the LogEntry of d and the size of its payload.
func (l *LoggingSink) entry(d *keybroker.Decision) (map[string]any, int, error) {
	payload, err := json.Marshal(d)
	if err != nil {
		return nil, 0, err
	}
	var jp map[string]any
	if err := json.Unmarshal(payload, &jp); err != nil {
		return nil, 0, err
	}
	jp["message"] = d.Message()
	return map[string]any{
		"severity":    d.Severity(),
		"timestamp":   d.Time.UTC().Format(time.RFC3339Nano),
		"insertId":    d.RequestID,
		"labels":      map[string]string{"decision": d.Decision, "reason": d.Reason, "component": "sealed-key-broker"},
		"jsonPayload": jp,
	}, len(payload) + 512, nil
}

func (l *LoggingSink) post(ctx context.Context, entries []map[string]any, partial bool) error {
	ep := l.Endpoint
	if ep == "" {
		ep = DefaultLoggingEndpoint
	}
	logID := l.LogID
	if logID == "" {
		logID = DefaultDecisionLogID
	}
	body := map[string]any{
		"logName":        "projects/" + l.Project + "/logs/" + url.PathEscape(logID),
		"resource":       l.Resource,
		"entries":        entries,
		"partialSuccess": partial,
	}
	return call(ctx, l.Client, l.Tokens, "logging", http.MethodPost, ep+"/v2/entries:write", body, nil)
}

var _ keybroker.BatchLog = (*LoggingSink)(nil)
