package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
)

// LintFinding is one finding of `sealed-compose lint --json` (runtime/composer/lint.Finding).
type LintFinding struct {
	Severity string `json:"severity"`
	App      string `json:"app"`
	File     string `json:"file,omitempty"`
	Field    string `json:"field,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// Lint gate modes. On pull requests an image that is still unbuilt cannot have an SBOM or a digest yet:
// the runtime image workflow builds it only after merge, and the pin PR then runs the full gate. A release
// allows nothing.
const (
	GateModePR      = "pr"
	GateModeRelease = "release"
)

// GateResult is the outcome of the lint gate.
type GateResult struct {
	Blocking []LintFinding // errors that fail the job
	Deferred []LintFinding // errors deferred to the pin PR and the release (pr mode only)
	Warnings []LintFinding
}

// LintGate classifies composer lint findings. unbuilt maps app id to its unbuilt image names; in pr mode
// unbuilt-image errors, and sbom-missing errors for unbuilt images, are deferred.
func LintGate(findings []LintFinding, mode string, unbuilt map[string][]string) (*GateResult, error) {
	if mode != GateModePR && mode != GateModeRelease {
		return nil, fmt.Errorf("unknown mode %q (want pr or release)", mode)
	}
	g := &GateResult{}
	for _, f := range findings {
		if f.Severity != "error" {
			g.Warnings = append(g.Warnings, f)
			continue
		}
		if mode == GateModePR && deferrable(f, unbuilt) {
			g.Deferred = append(g.Deferred, f)
			continue
		}
		g.Blocking = append(g.Blocking, f)
	}
	return g, nil
}

func deferrable(f LintFinding, unbuilt map[string][]string) bool {
	switch f.Code {
	case "unbuilt-image":
		return true
	case "sbom-missing":
		img, ok := strings.CutSuffix(strings.TrimPrefix(f.File, "sbom/"), ".spdx.json")
		return ok && contains(unbuilt[f.App], img)
	}
	return false
}

// Annotate writes GitHub workflow commands for the findings (errors as ::error, the rest as ::warning).
func (g *GateResult) Annotate(w io.Writer) {
	emit := func(level string, f LintFinding) {
		file := ""
		if f.App != "" && !strings.Contains(f.App, "/") && !strings.HasSuffix(f.App, ".tar") {
			file = path.Join(CatalogDir, f.App, f.File)
		}
		msg := f.Message
		if f.Field != "" {
			msg = f.Field + ": " + msg
		}
		msg = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(msg)
		if file != "" {
			fmt.Fprintf(w, "::%s file=%s,title=%s::%s\n", level, file, f.Code, msg)
		} else {
			fmt.Fprintf(w, "::%s title=%s::%s: %s\n", level, f.Code, f.App, msg)
		}
	}
	for _, f := range g.Blocking {
		emit("error", f)
	}
	for _, f := range g.Deferred {
		emit("notice", f)
	}
	for _, f := range g.Warnings {
		emit("warning", f)
	}
}

// ParseLintFindings reads `sealed-compose lint --json` output.
func ParseLintFindings(raw []byte) ([]LintFinding, error) {
	var out []LintFinding
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("lint findings: %w", err)
	}
	return out, nil
}
