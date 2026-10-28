package attest

import (
	"fmt"
	"slices"

	"github.com/google/go-tdx-guest/pcs"
	"go.yaml.in/yaml/v3"
)

var knownTCBStatuses = []string{
	string(pcs.TcbComponentStatusUpToDate),
	string(pcs.TcbComponentStatusSwHardeningNeeded),
	string(pcs.TcbComponentStatusConfigurationNeeded),
	string(pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded),
	string(pcs.TcbComponentStatusOutOfDate),
	string(pcs.TcbComponentStatusOutOfDateConfigurationNeeded),
	string(pcs.TcbComponentStatusRevoked),
	string(pcs.TcbComponentStatusRelaunchAdvisedConfigurationNeeded),
}

// TCBPolicy decides which Intel TCB statuses are acceptable (config/defaults.yaml tcb_policy, spec 5.7).
type TCBPolicy struct {
	// AllowedStatuses applies to both the TDX TCB level and the QE identity level.
	AllowedStatuses []string `yaml:"allowed_statuses" json:"allowedStatuses"`
	// AllowedAdvisoryIDs, when non-empty, restricts the Intel advisories accepted on a level that is not
	// UpToDate. Empty accepts any advisory of an allowed status.
	AllowedAdvisoryIDs []string `yaml:"allowed_advisory_ids" json:"allowedAdvisoryIds,omitempty"`
}

// DefaultTCBPolicy matches config/defaults.yaml.
func DefaultTCBPolicy() TCBPolicy {
	return TCBPolicy{AllowedStatuses: []string{
		string(pcs.TcbComponentStatusUpToDate),
		string(pcs.TcbComponentStatusSwHardeningNeeded),
	}}
}

// TCBPolicyFromDefaults reads tcb_policy from the contents of config/defaults.yaml.
func TCBPolicyFromDefaults(defaultsYAML []byte) (TCBPolicy, error) {
	var doc struct {
		TCBPolicy *TCBPolicy `yaml:"tcb_policy"`
	}
	if err := yaml.Unmarshal(defaultsYAML, &doc); err != nil {
		return TCBPolicy{}, fmt.Errorf("parse defaults: %w", err)
	}
	if doc.TCBPolicy == nil {
		return TCBPolicy{}, fmt.Errorf("defaults: tcb_policy missing")
	}
	return *doc.TCBPolicy, doc.TCBPolicy.Validate()
}

// Validate rejects empty policies and unknown status names.
func (p TCBPolicy) Validate() error {
	if len(p.AllowedStatuses) == 0 {
		return fmt.Errorf("tcb policy: allowed_statuses is empty")
	}
	for _, s := range p.AllowedStatuses {
		if !slices.Contains(knownTCBStatuses, s) {
			return fmt.Errorf("tcb policy: unknown status %q", s)
		}
	}
	return nil
}

// Check applies the policy to the matched TDX and QE TCB levels. It fails closed on empty statuses.
func (p TCBPolicy) Check(tdx, qe pcs.TcbLevel) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrTCBStatus, err)
	}
	if err := p.checkLevel("TDX", tdx); err != nil {
		return err
	}
	return p.checkLevel("QE", qe)
}

func (p TCBPolicy) checkLevel(what string, l pcs.TcbLevel) error {
	status := string(l.TcbStatus)
	if !slices.Contains(p.AllowedStatuses, status) {
		return fmt.Errorf("%w: %s TCB status %q is not allowed (allowed %v, advisories %v)", ErrTCBStatus, what, status, p.AllowedStatuses, l.AdvisoryIDs)
	}
	if status == string(pcs.TcbComponentStatusUpToDate) || len(p.AllowedAdvisoryIDs) == 0 {
		return nil
	}
	for _, a := range l.AdvisoryIDs {
		if !slices.Contains(p.AllowedAdvisoryIDs, a) {
			return fmt.Errorf("%w: %s TCB status %q carries advisory %s, which is not allowed", ErrTCBStatus, what, status, a)
		}
	}
	return nil
}
