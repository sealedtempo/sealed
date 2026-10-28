package attest

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-tdx-guest/pcs"
)

func level(status pcs.TcbComponentStatus, adv ...string) pcs.TcbLevel {
	return pcs.TcbLevel{TcbStatus: status, AdvisoryIDs: adv}
}

func TestTCBPolicyFromRepoDefaults(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := TCBPolicyFromDefaults(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.AllowedStatuses, DefaultTCBPolicy().AllowedStatuses) {
		t.Fatalf("defaults.yaml tcb_policy %v differs from DefaultTCBPolicy", p.AllowedStatuses)
	}
}

func TestTCBPolicyCheck(t *testing.T) {
	def := DefaultTCBPolicy()
	up := level(pcs.TcbComponentStatusUpToDate)
	for name, tc := range map[string]struct {
		p       TCBPolicy
		tdx, qe pcs.TcbLevel
		ok      bool
	}{
		"up to date":                {def, up, up, true},
		"sw hardening":              {def, level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1"), up, true},
		"out of date":               {def, level(pcs.TcbComponentStatusOutOfDate), up, false},
		"revoked":                   {def, level(pcs.TcbComponentStatusRevoked), up, false},
		"config needed":             {def, level(pcs.TcbComponentStatusConfigurationNeeded), up, false},
		"qe out of date":            {def, up, level(pcs.TcbComponentStatusOutOfDate), false},
		"empty status":              {def, pcs.TcbLevel{}, up, false},
		"empty policy fails closed": {TCBPolicy{}, up, up, false},
		"advisory allowed": {
			TCBPolicy{AllowedStatuses: def.AllowedStatuses, AllowedAdvisoryIDs: []string{"INTEL-SA-1"}},
			level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1"), up, true,
		},
		"advisory not allowed": {
			TCBPolicy{AllowedStatuses: def.AllowedStatuses, AllowedAdvisoryIDs: []string{"INTEL-SA-1"}},
			level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1", "INTEL-SA-2"), up, false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.p.Check(tc.tdx, tc.qe)
			if (err == nil) != tc.ok {
				t.Fatalf("Check = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrTCBStatus) {
				t.Fatalf("error %v does not wrap ErrTCBStatus", err)
			}
		})
	}
}

func TestTCBPolicyValidate(t *testing.T) {
	if _, err := TCBPolicyFromDefaults([]byte("tcb_policy:\n  allowed_statuses: [UpToDate, Bogus]\n")); err == nil {
		t.Fatal("unknown status accepted")
	}
	if _, err := TCBPolicyFromDefaults([]byte("codename: x\n")); err == nil {
		t.Fatal("missing tcb_policy accepted")
	}
	if _, err := NewVerifier(VerifierOptions{TCBPolicy: TCBPolicy{AllowedStatuses: []string{"Nope"}}}); err == nil {
		t.Fatal("NewVerifier accepted an invalid policy")
	}
}
