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

func eval(platform pcs.TcbLevel, module *pcs.TcbLevel, qe pcs.TcbLevel) *TCBEvaluation {
	return &TCBEvaluation{Platform: platform, Module: module, QE: qe, Status: convergeTCBStatus(platform.TcbStatus, module), AdvisoryIDs: unionAdvisories(platform, module)}
}

func TestTCBPolicyCheck(t *testing.T) {
	def := DefaultTCBPolicy()
	up := level(pcs.TcbComponentStatusUpToDate)
	lenient := TCBPolicy{AllowedStatuses: []string{"UpToDate", "SWHardeningNeeded", "OutOfDate"}}
	modUp, modOld := level(pcs.TcbComponentStatusUpToDate), level(pcs.TcbComponentStatusOutOfDate, "INTEL-SA-9")
	for name, tc := range map[string]struct {
		p  TCBPolicy
		ev *TCBEvaluation
		ok bool
	}{
		"up to date":                        {def, eval(up, nil, up), true},
		"up to date with module":            {def, eval(up, &modUp, up), true},
		"sw hardening":                      {def, eval(level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1"), nil, up), true},
		"out of date":                       {def, eval(level(pcs.TcbComponentStatusOutOfDate), nil, up), false},
		"revoked":                           {def, eval(level(pcs.TcbComponentStatusRevoked), nil, up), false},
		"config needed":                     {def, eval(level(pcs.TcbComponentStatusConfigurationNeeded), nil, up), false},
		"qe out of date":                    {def, eval(up, nil, level(pcs.TcbComponentStatusOutOfDate)), false},
		"platform outdated, module current": {def, eval(level(pcs.TcbComponentStatusOutOfDate, "INTEL-SA-2"), &modUp, up), false},
		"platform current, module outdated": {def, eval(up, &modOld, up), false},
		"empty status":                      {def, eval(pcs.TcbLevel{}, nil, up), false},
		"nil evaluation":                    {def, nil, false},
		"empty policy fails closed":         {TCBPolicy{}, eval(up, nil, up), false},
		"lenient accepts outdated module":   {lenient, eval(up, &modOld, up), true},
		"advisory allowed": {
			TCBPolicy{AllowedStatuses: def.AllowedStatuses, AllowedAdvisoryIDs: []string{"INTEL-SA-1"}},
			eval(level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1"), nil, up), true,
		},
		"advisory not allowed": {
			TCBPolicy{AllowedStatuses: def.AllowedStatuses, AllowedAdvisoryIDs: []string{"INTEL-SA-1"}},
			eval(level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1", "INTEL-SA-2"), nil, up), false,
		},
		"module advisory checked against the allowlist": {
			TCBPolicy{AllowedStatuses: lenient.AllowedStatuses, AllowedAdvisoryIDs: []string{"INTEL-SA-1"}},
			eval(level(pcs.TcbComponentStatusSwHardeningNeeded, "INTEL-SA-1"), &modOld, up), false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.p.Check(tc.ev)
			if (err == nil) != tc.ok {
				t.Fatalf("Check = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrTCBStatus) {
				t.Fatalf("error %v does not wrap ErrTCBStatus", err)
			}
		})
	}
}

func TestConvergeTCBStatus(t *testing.T) {
	const (
		up     = pcs.TcbComponentStatusUpToDate
		swh    = pcs.TcbComponentStatusSwHardeningNeeded
		cfg    = pcs.TcbComponentStatusConfigurationNeeded
		cfgSW  = pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded
		old    = pcs.TcbComponentStatusOutOfDate
		oldCfg = pcs.TcbComponentStatusOutOfDateConfigurationNeeded
		rev    = pcs.TcbComponentStatusRevoked
	)
	mod := func(s pcs.TcbComponentStatus) *pcs.TcbLevel { l := level(s); return &l }
	for _, tc := range []struct {
		platform pcs.TcbComponentStatus
		module   *pcs.TcbLevel
		want     pcs.TcbComponentStatus
	}{
		{up, nil, up},
		{old, nil, old},
		{up, mod(up), up},
		{old, mod(up), old}, // the platform level is never hidden by a current module
		{swh, mod(up), swh},
		{up, mod(old), old},
		{swh, mod(old), old},
		{cfg, mod(old), oldCfg},
		{cfgSW, mod(old), oldCfg},
		{rev, mod(old), rev},
		{up, mod(rev), rev},
		{old, mod(swh), old},
		{up, mod(swh), swh},
	} {
		if got := convergeTCBStatus(tc.platform, tc.module); got != tc.want {
			m := pcs.TcbComponentStatus("none")
			if tc.module != nil {
				m = tc.module.TcbStatus
			}
			t.Errorf("converge(%s, %s) = %s, want %s", tc.platform, m, got, tc.want)
		}
	}
	if got := unionAdvisories(level(old, "B", "A"), &pcs.TcbLevel{AdvisoryIDs: []string{"C", "A"}}); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("union %v", got)
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
