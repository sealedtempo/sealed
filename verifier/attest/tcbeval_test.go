package attest

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/verify"
)

// mapSource serves collateral bodies from memory: the signature checks are bypassed, so tests can edit levels.
type mapSource map[string][]byte

func (m mapSource) body(url string) ([]byte, bool) { b, ok := m[url]; return b, ok }

// recordedSource loads the recorded TCB info and QE identity of fixture `name`.
func recordedSource(t *testing.T, name, fmspc string) mapSource {
	t.Helper()
	g, err := NewCachingGetter(CacheOptions{Dir: filepath.Join("testdata", "pcs", name), TTL: 100 * 365 * 24 * time.Hour,
		Inner: offlineGetter{}, Now: func() time.Time { return recordedTime(t, name) }})
	if err != nil {
		t.Fatal(err)
	}
	src := mapSource{}
	for _, u := range []string{pcs.TcbInfoURL(fmspc), pcs.QeIdentityURL()} {
		_, b, err := g.Get(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		src[u] = b
	}
	return src
}

// editTcbInfo rewrites the tcbInfo of src through edit (on its generic JSON form).
func editTcbInfo(t *testing.T, src mapSource, fmspc string, edit func(info map[string]any)) mapSource {
	t.Helper()
	out := mapSource{}
	for k, v := range src {
		out[k] = v
	}
	var doc map[string]any
	if err := json.Unmarshal(src[pcs.TcbInfoURL(fmspc)], &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc["tcbInfo"].(map[string]any))
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out[pcs.TcbInfoURL(fmspc)] = raw
	return out
}

// setModuleLevel sets the status and advisories of every level of module identity id.
func setModuleLevel(info map[string]any, id string, status string, advisories []any) {
	for _, m := range info["tdxModuleIdentities"].([]any) {
		mod := m.(map[string]any)
		if mod["id"] != id {
			continue
		}
		for _, l := range mod["tcbLevels"].([]any) {
			l.(map[string]any)["tcbStatus"] = status
			l.(map[string]any)["advisoryIDs"] = advisories
		}
	}
}

// setPlatformLevels sets the status and advisories of every platform TCB level.
func setPlatformLevels(info map[string]any, status string, advisories []any) {
	for _, l := range info["tcbLevels"].([]any) {
		l.(map[string]any)["tcbStatus"] = status
		l.(map[string]any)["advisoryIDs"] = advisories
	}
}

func pckExtensions(t *testing.T, q *Quote) *pcs.PckExtensions {
	t.Helper()
	chain, err := verify.ExtractChainFromQuote(q.proto)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

const gceFMSPC = "00806f050000"

// The real GCE platform level (CPU SVN, PCE SVN, TDX components) and its advisories in the recorded collateral.
var gcePlatformAdvisories = []string{
	"INTEL-SA-01010", "INTEL-SA-01036", "INTEL-SA-01076", "INTEL-SA-01079", "INTEL-SA-01099", "INTEL-SA-01103",
	"INTEL-SA-01111", "INTEL-SA-01192", "INTEL-SA-01245", "INTEL-SA-01312", "INTEL-SA-01313",
}

func TestEvaluateTCBRecordedGCE(t *testing.T) {
	q, err := ParseQuote(gceQuote(t), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if q.TeeTcbSvn[1] == 0 {
		t.Fatal("fixture should carry a TDX module major version")
	}
	ev, err := evaluateTCB(q, pckExtensions(t, q), recordedSource(t, "v4_gce_cos113", gceFMSPC))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Platform.TcbStatus != pcs.TcbComponentStatusOutOfDate || ev.Module == nil || ev.Module.TcbStatus != pcs.TcbComponentStatusOutOfDate {
		t.Fatalf("platform %s module %+v", ev.Platform.TcbStatus, ev.Module)
	}
	if !slices.Equal(ev.Platform.AdvisoryIDs, gcePlatformAdvisories) {
		t.Fatalf("platform advisories %v, want %v", ev.Platform.AdvisoryIDs, gcePlatformAdvisories)
	}
	// The module level's advisories are a subset; the union is the platform list here.
	if !slices.Equal(ev.AdvisoryIDs, gcePlatformAdvisories) || ev.Status != pcs.TcbComponentStatusOutOfDate {
		t.Fatalf("converged %s %v", ev.Status, ev.AdvisoryIDs)
	}
}

// TestTCBPlatformLevelIsEvaluated is the regression test for module-only evaluation: on TDX module 1.x (all GCP
// C3 quotes) an UpToDate module must not hide an OutOfDate platform (microcode, PCE), and the reverse.
func TestTCBPlatformLevelIsEvaluated(t *testing.T) {
	q, err := ParseQuote(gceQuote(t), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ext := pckExtensions(t, q)
	base := recordedSource(t, "v4_gce_cos113", gceFMSPC)
	strict := recordedVerifier(t, "v4_gce_cos113", DefaultTCBPolicy(), 0)
	lenient := recordedVerifier(t, "v4_gce_cos113", TCBPolicy{AllowedStatuses: []string{"UpToDate", "OutOfDate"}}, 0)

	t.Run("module up to date, platform out of date", func(t *testing.T) {
		src := editTcbInfo(t, base, gceFMSPC, func(info map[string]any) { setModuleLevel(info, "TDX_01", "UpToDate", nil) })
		if _, err := strict.applyTCB(q, ext, src); !errors.Is(err, ErrTCBStatus) {
			t.Fatalf("outdated platform accepted by the default policy: %v", err)
		}
		res, err := lenient.applyTCB(q, ext, src)
		if err != nil {
			t.Fatal(err)
		}
		if res.TCBStatus != "OutOfDate" || res.PlatformTCBStatus != "OutOfDate" || res.ModuleTCBStatus != "UpToDate" {
			t.Fatalf("statuses %+v", res)
		}
		if !slices.Equal(res.AdvisoryIDs, gcePlatformAdvisories) {
			t.Fatalf("advisories %v, want the platform's %v", res.AdvisoryIDs, gcePlatformAdvisories)
		}
		// The advisory allowlist sees the platform advisories, not only the module's.
		moduleOnly := TCBPolicy{AllowedStatuses: []string{"UpToDate", "OutOfDate"}, AllowedAdvisoryIDs: []string{"INTEL-SA-01036", "INTEL-SA-01099", "INTEL-SA-01192", "INTEL-SA-01245", "INTEL-SA-01312"}}
		if _, err := recordedVerifier(t, "v4_gce_cos113", moduleOnly, 0).applyTCB(q, ext, src); !errors.Is(err, ErrTCBStatus) {
			t.Fatalf("platform advisories not checked against the allowlist: %v", err)
		}
	})
	t.Run("platform up to date, module out of date", func(t *testing.T) {
		src := editTcbInfo(t, base, gceFMSPC, func(info map[string]any) { setPlatformLevels(info, "UpToDate", nil) })
		_, err := strict.applyTCB(q, ext, src)
		if !errors.Is(err, ErrTCBStatus) {
			t.Fatalf("outdated module accepted: %v", err)
		}
		res, err := lenient.applyTCB(q, ext, src)
		if err != nil || res.TCBStatus != "OutOfDate" || res.PlatformTCBStatus != "UpToDate" || res.ModuleTCBStatus != "OutOfDate" {
			t.Fatalf("result %+v %v", res, err)
		}
	})
	t.Run("both up to date", func(t *testing.T) {
		src := editTcbInfo(t, base, gceFMSPC, func(info map[string]any) {
			setPlatformLevels(info, "UpToDate", nil)
			setModuleLevel(info, "TDX_01", "UpToDate", nil)
		})
		res, err := strict.applyTCB(q, ext, src)
		if err != nil || res.TCBStatus != "UpToDate" || len(res.AdvisoryIDs) != 0 {
			t.Fatalf("result %+v %v", res, err)
		}
	})
	t.Run("module identity missing", func(t *testing.T) {
		src := editTcbInfo(t, base, gceFMSPC, func(info map[string]any) { info["tdxModuleIdentities"] = []any{} })
		if _, err := lenient.applyTCB(q, ext, src); !errors.Is(err, ErrTCBStatus) {
			t.Fatalf("missing module identity: %v", err)
		}
	})
	t.Run("module signer differs", func(t *testing.T) {
		src := editTcbInfo(t, base, gceFMSPC, func(info map[string]any) {
			for _, m := range info["tdxModuleIdentities"].([]any) {
				m.(map[string]any)["mrsigner"] = "01" + strings.Repeat("00", 47)
			}
		})
		if _, err := lenient.applyTCB(q, ext, src); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("foreign module signer: %v", err)
		}
	})
	t.Run("no platform level matches", func(t *testing.T) {
		src := editTcbInfo(t, base, gceFMSPC, func(info map[string]any) {
			for _, l := range info["tcbLevels"].([]any) {
				l.(map[string]any)["tcb"].(map[string]any)["pcesvn"] = 65535
			}
		})
		if _, err := lenient.applyTCB(q, ext, src); !errors.Is(err, ErrTCBStatus) {
			t.Fatalf("unmatched platform: %v", err)
		}
	})
	t.Run("collateral not recorded", func(t *testing.T) {
		if _, err := lenient.applyTCB(q, ext, mapSource{}); !errors.Is(err, ErrQuoteInvalid) {
			t.Fatalf("missing collateral: %v", err)
		}
	})
}

func TestRecordingGetterKeepsVerifiedBodies(t *testing.T) {
	inner := &countingGetter{}
	rec := newRecordingGetter(inner)
	if _, _, err := rec.GetContext(context.Background(), tcbURL); err != nil {
		t.Fatal(err)
	}
	if b, ok := rec.body(tcbURL); !ok || string(b) != "body:"+tcbURL {
		t.Fatalf("body %q %v", b, ok)
	}
	inner.fail = true
	if _, _, err := rec.Get("https://api.trustedservices.intel.com/other"); err == nil {
		t.Fatal("error swallowed")
	}
	if _, ok := rec.body("https://api.trustedservices.intel.com/other"); ok {
		t.Fatal("failed fetch recorded")
	}
}
