package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxWaiverDays is how far in the future a waiver may expire, counted from the day of the scan.
const MaxWaiverDays = 90

var (
	vulnIDRe = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]*-[0-9A-Za-z:._-]+)$`)
	dateRe   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// Waiver is one accepted Grype finding (catalog/apps/<id>/waivers.yaml, format of the scraper app).
type Waiver struct {
	ID      string `yaml:"id" json:"id"`
	Image   string `yaml:"image" json:"image"`
	Package string `yaml:"package" json:"package"`
	Reason  string `yaml:"reason" json:"reason"`
	Expires string `yaml:"expires" json:"expires"`
}

// WaiverFile is a parsed waivers.yaml.
type WaiverFile struct {
	Path    string
	Waivers []Waiver
	// Legacy is set for a bare list (the version 1 mapping is the canonical format).
	Legacy bool
}

// ParseWaivers parses waivers.yaml. The canonical format is {version: 1, waivers: [...]}; a bare list of
// the same entries is accepted and reported as Legacy so lint can ask for the canonical form.
func ParseWaivers(path string, raw []byte) (*WaiverFile, error) {
	wf := &WaiverFile{Path: path}
	var probe yaml.Node
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(probe.Content) == 0 {
		return nil, fmt.Errorf("%s: empty file (write `version: 1` and `waivers: []`)", path)
	}
	switch probe.Content[0].Kind {
	case yaml.SequenceNode:
		wf.Legacy = true
		if err := decodeStrict(raw, &wf.Waivers); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case yaml.MappingNode:
		var doc struct {
			Version int      `yaml:"version"`
			Waivers []Waiver `yaml:"waivers"`
		}
		if err := decodeStrict(raw, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if doc.Version != 1 {
			return nil, fmt.Errorf("%s: version must be 1", path)
		}
		if yamlValue(probe.Content[0], "waivers") == nil {
			return nil, fmt.Errorf("%s: waivers list is missing (write `waivers: []` when there are none)", path)
		}
		wf.Waivers = doc.Waivers
	default:
		return nil, fmt.Errorf("%s: expected a mapping with version and waivers", path)
	}
	return wf, nil
}

// LoadWaivers reads and parses a waivers.yaml file.
func LoadWaivers(path string) (*WaiverFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseWaivers(path, raw)
}

func decodeStrict(raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	return dec.Decode(out)
}

// Validate checks every entry: known id format, an image of the app, a package, a reason, and an expiry
// date that is real and at most MaxWaiverDays after today. Expired entries are not errors here (they stop
// applying, and Evaluate reports them).
func (wf *WaiverFile) Validate(images []string, today time.Time) []error {
	var errs []error
	seen := map[string]bool{}
	for i, w := range wf.Waivers {
		at := fmt.Sprintf("%s: waivers[%d]", wf.Path, i)
		if !vulnIDRe.MatchString(w.ID) {
			errs = append(errs, fmt.Errorf("%s: id %q is not a CVE, GHSA or other advisory id", at, w.ID))
		}
		if !contains(images, w.Image) {
			errs = append(errs, fmt.Errorf("%s: image %q is not one of %s", at, w.Image, strings.Join(images, ", ")))
		}
		if strings.TrimSpace(w.Package) == "" {
			errs = append(errs, fmt.Errorf("%s: package is required", at))
		}
		if len(strings.TrimSpace(w.Reason)) < 10 {
			errs = append(errs, fmt.Errorf("%s: reason must say why the finding does not apply or what blocks the fix", at))
		}
		exp, err := parseDay(w.Expires)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: expires %q is not a YYYY-MM-DD date", at, w.Expires))
		case exp.Sub(day(today)) > MaxWaiverDays*24*time.Hour:
			errs = append(errs, fmt.Errorf("%s: expires %s is more than %d days after %s", at, w.Expires, MaxWaiverDays, day(today).Format(time.DateOnly)))
		}
		key := w.ID + "|" + w.Image + "|" + w.Package
		if seen[key] {
			errs = append(errs, fmt.Errorf("%s: duplicate waiver for %s in %s (%s)", at, w.ID, w.Package, w.Image))
		}
		seen[key] = true
	}
	return errs
}

func parseDay(s string) (time.Time, error) {
	if !dateRe.MatchString(s) {
		return time.Time{}, fmt.Errorf("bad date")
	}
	return time.Parse(time.DateOnly, s)
}

func day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// expired reports whether the waiver no longer applies: it applies through its expiry day (UTC).
func (w Waiver) expired(today time.Time) bool {
	exp, err := parseDay(w.Expires)
	return err != nil || day(today).After(exp)
}

// GrypeReport is the part of `grype -o json` the gate reads.
type GrypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Fix      struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		DB      any    `json:"db"`
	} `json:"descriptor"`
}

// ParseGrype parses a Grype JSON report.
func ParseGrype(raw []byte) (*GrypeReport, error) {
	var r GrypeReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("grype report: %w", err)
	}
	if r.Matches == nil && !bytes.Contains(raw, []byte(`"matches"`)) {
		return nil, fmt.Errorf("grype report: no matches field (not grype -o json output)")
	}
	return &r, nil
}

// ScanFinding is one deduplicated vulnerability in one package.
type ScanFinding struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Severity string   `json:"severity"`
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Type     string   `json:"type,omitempty"`
	Fix      string   `json:"fix,omitempty"`
	Note     string   `json:"note,omitempty"` // the waiver reason, for accepted findings
	Expires  string   `json:"expires,omitempty"`
}

// ScanSummary is the result of the waiver gate for one image.
type ScanSummary struct {
	Image          string         `json:"image"`
	Scanner        string         `json:"scanner"`
	ScannerVersion string         `json:"scannerVersion,omitempty"`
	Counts         map[string]int `json:"counts"`
	Unwaived       []ScanFinding  `json:"unwaived"`      // critical findings without a valid waiver: the gate fails
	Accepted       []ScanFinding  `json:"accepted"`      // findings matched by a waiver that has not expired
	ExpiredHits    []ScanFinding  `json:"expiredHits"`   // critical findings whose only waiver expired (also in Unwaived)
	UnusedWaivers  []Waiver       `json:"unusedWaivers"` // waivers for this image that matched nothing
}

// OK reports whether the gate passes.
func (s *ScanSummary) OK() bool { return len(s.Unwaived) == 0 }

var severityOrder = []string{"critical", "high", "medium", "low", "negligible", "unknown"}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if contains(severityOrder, s) {
		return s
	}
	return "unknown"
}

// Evaluate applies the waivers of one image to a Grype report. A finding is waived when a waiver for the
// image and package names its id or one of its related ids and has not expired. Only critical findings
// fail the gate (spec 6.8).
func Evaluate(r *GrypeReport, image string, wf *WaiverFile, today time.Time) *ScanSummary {
	s := &ScanSummary{Image: image, Scanner: "grype", ScannerVersion: r.Descriptor.Version, Counts: map[string]int{},
		Unwaived: []ScanFinding{}, Accepted: []ScanFinding{}, ExpiredHits: []ScanFinding{}, UnusedWaivers: []Waiver{}}
	for _, sev := range severityOrder {
		s.Counts[sev] = 0
	}
	var waivers []Waiver
	if wf != nil {
		for _, w := range wf.Waivers {
			if w.Image == image {
				waivers = append(waivers, w)
			}
		}
	}
	used := make([]bool, len(waivers))
	seen := map[string]bool{}
	for _, m := range r.Matches {
		f := ScanFinding{ID: m.Vulnerability.ID, Severity: normSeverity(m.Vulnerability.Severity),
			Package: m.Artifact.Name, Version: m.Artifact.Version, Type: m.Artifact.Type}
		for _, rel := range m.RelatedVulnerabilities {
			if rel.ID != f.ID && !contains(f.Aliases, rel.ID) {
				f.Aliases = append(f.Aliases, rel.ID)
			}
		}
		if m.Vulnerability.Fix.State == "fixed" && len(m.Vulnerability.Fix.Versions) > 0 {
			f.Fix = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		key := f.ID + "|" + f.Package + "|" + f.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		s.Counts[f.Severity]++

		matched, expiredOnly := -1, false
		for i, w := range waivers {
			if w.Package != f.Package || (w.ID != f.ID && !contains(f.Aliases, w.ID)) {
				continue
			}
			used[i] = true
			if w.expired(today) {
				expiredOnly = true
				continue
			}
			matched = i
			break
		}
		switch {
		case matched >= 0:
			f.Note, f.Expires = waivers[matched].Reason, waivers[matched].Expires
			s.Accepted = append(s.Accepted, f)
		case f.Severity == "critical":
			s.Unwaived = append(s.Unwaived, f)
			if expiredOnly {
				s.ExpiredHits = append(s.ExpiredHits, f)
			}
		}
	}
	for i, w := range waivers {
		if !used[i] {
			s.UnusedWaivers = append(s.UnusedWaivers, w)
		}
	}
	for _, list := range [][]ScanFinding{s.Unwaived, s.Accepted, s.ExpiredHits} {
		sort.Slice(list, func(i, j int) bool {
			if list[i].ID != list[j].ID {
				return list[i].ID < list[j].ID
			}
			return list[i].Package < list[j].Package
		})
	}
	return s
}

// Report renders a human-readable gate result.
func (s *ScanSummary) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: critical %d, high %d, medium %d, low %d, negligible %d, unknown %d\n", s.Image,
		s.Counts["critical"], s.Counts["high"], s.Counts["medium"], s.Counts["low"], s.Counts["negligible"], s.Counts["unknown"])
	for _, f := range s.Accepted {
		fmt.Fprintf(&b, "  waived    %s %s %s (%s, until %s): %s\n", f.Severity, f.ID, f.Package, f.Version, f.Expires, f.Note)
	}
	for _, f := range s.Unwaived {
		extra := ""
		if f.Fix != "" {
			extra = ", fixed in " + f.Fix
		}
		fmt.Fprintf(&b, "  UNWAIVED  critical %s %s %s%s\n", f.ID, f.Package, f.Version, extra)
	}
	for _, f := range s.ExpiredHits {
		fmt.Fprintf(&b, "  expired waiver no longer covers %s in %s\n", f.ID, f.Package)
	}
	for _, w := range s.UnusedWaivers {
		fmt.Fprintf(&b, "  unused waiver %s for %s (remove it if the finding is gone)\n", w.ID, w.Package)
	}
	return b.String()
}
