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
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	var jp map[string]any
	if err := json.Unmarshal(payload, &jp); err != nil {
		return err
	}
	jp["message"] = d.Message()
	ep := l.Endpoint
	if ep == "" {
		ep = DefaultLoggingEndpoint
	}
	logID := l.LogID
	if logID == "" {
		logID = DefaultDecisionLogID
	}
	body := map[string]any{
		"logName":  "projects/" + l.Project + "/logs/" + url.PathEscape(logID),
		"resource": l.Resource,
		"entries": []map[string]any{{
			"severity":    d.Severity(),
			"timestamp":   d.Time.UTC().Format(time.RFC3339Nano),
			"insertId":    d.RequestID,
			"labels":      map[string]string{"decision": d.Decision, "reason": d.Reason, "component": "sealed-key-broker"},
			"jsonPayload": jp,
		}},
		"partialSuccess": false,
	}
	return call(ctx, l.Client, l.Tokens, "logging", http.MethodPost, ep+"/v2/entries:write", body, nil)
}
