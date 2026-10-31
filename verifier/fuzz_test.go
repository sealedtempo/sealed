package verify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sealedtempo/sealed/runtime/composer/cjson"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
)

// Fuzz targets for the evidence bundle the platform and the agent submit and
// the /attest document a live verification reads. Both run every check
// against an in-memory chain and a simulated quote. The property is that a
// report passes only when the input says what the original said: the fields
// the checks bind (ids, hashes, addresses, quote, config, compose, the RTMR3
// events) decode to the original values. Anything else that passes would be
// evidence the verifier vouches for without the TD having produced it.

type fuzzEnv struct {
	w    *fixture.World
	m    *fixture.MemChain
	b    *verify.Bundle
	deps verify.Deps
	opts verify.Options
}

func newFuzzEnv(tb testing.TB) *fuzzEnv {
	w := fixture.NewWorld(4217, testAddrs, customer, enclave, fixture.SimImageID(false))
	m := fixture.NewMemChain(4217, testAddrs)
	b := w.Bundle(m.Now)
	w.Populate(m, b, true)
	v, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: true, Getter: offline{}})
	if err != nil {
		tb.Fatal(err)
	}
	e := &fuzzEnv{w: w, m: m, b: b,
		deps: verify.Deps{Quotes: v, Chain: m, Composer: fixture.Composer{}, Now: func() time.Time { return time.Unix(int64(m.Now)+10, 0) }},
		opts: verify.Options{ChainID: 4217, RequireOnchainRecord: true, AcceptSimulated: true},
	}
	m.HeadAt = func() time.Time { return e.deps.Now().Add(-2 * time.Second) }
	return e
}

func d32(s string) ([32]byte, bool) { b, err := hexb.Decode32(s); return b, err == nil }
func d20(s string) ([20]byte, bool) { b, err := hexb.Decode20(s); return b, err == nil }

func idSet(ss []string) ([][32]byte, bool) {
	var out [][32]byte
	for _, s := range ss {
		id, ok := d32(s)
		if !ok {
			return nil, false
		}
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return out, true
}

func cjsonHash(raw []byte) ([32]byte, bool) {
	c, err := cjson.Canonicalize(raw)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(c), true
}

// runtimeEvents returns the imr 3 events of a raw event log (a JSON array, or
// a JSON string holding one), the part RTMR3 binds.
func runtimeEvents(raw []byte) ([]attest.Event, bool) {
	var inner string
	if json.Unmarshal(raw, &inner) == nil {
		raw = []byte(inner)
	}
	evs, err := attest.ParseEventLog(raw)
	if err != nil {
		return nil, false
	}
	_, rt, err := attest.ReplayRTMR3(evs)
	return rt, err == nil
}

func sameRuntime(a, b []attest.Event) bool {
	return slices.EqualFunc(a, b, func(x, y attest.Event) bool {
		return x.Event == y.Event && x.EventPayload == y.EventPayload && x.Digest == y.Digest
	})
}

// sameEvidence reports which bound field of got differs from want, or "".
func sameEvidence(want, got *verify.Bundle) string {
	eq32 := func(a, b string) bool { x, ok1 := d32(a); y, ok2 := d32(b); return ok1 && ok2 && x == y }
	eq20 := func(a, b string) bool { x, ok1 := d20(a); y, ok2 := d20(b); return ok1 && ok2 && x == y }
	switch {
	case want.Schema != got.Schema || want.Runtime != got.Runtime:
		return "schema or runtime"
	case want.ChainID != got.ChainID || want.AttestedAt != got.AttestedAt:
		return "chainId or attestedAt"
	case !eq20(want.Contracts.PlatformRegistry, got.Contracts.PlatformRegistry) || !eq20(want.Contracts.AppRegistry, got.Contracts.AppRegistry) ||
		!eq20(want.Contracts.DeploymentRegistry, got.Contracts.DeploymentRegistry):
		return "contracts"
	case !eq32(want.DeploymentID, got.DeploymentID) || !eq32(want.ImageID, got.ImageID) || !eq32(want.ConfigHash, got.ConfigHash) ||
		!eq32(want.StackHash, got.StackHash) || !eq32(want.Nonce2, got.Nonce2) || !eq32(want.QuoteHash, got.QuoteHash) ||
		!eq32(want.EventLogHash, got.EventLogHash):
		return "a 32-byte field"
	case !eq20(want.Customer, got.Customer) || !eq20(want.EnclaveSigner, got.EnclaveSigner):
		return "customer or enclaveSigner"
	case want.AppCompose != got.AppCompose:
		return "appCompose"
	}
	wq, _ := hexb.Decode(want.Quote, -1)
	gq, err := hexb.Decode(got.Quote, -1)
	if err != nil || !bytes.Equal(wq, gq) {
		return "quote"
	}
	wi, _ := idSet(want.ReleaseIDs)
	gi, ok := idSet(got.ReleaseIDs)
	if !ok || !slices.Equal(wi, gi) {
		return "releaseIds"
	}
	wc, _ := cjsonHash(want.Config)
	gc, ok := cjsonHash(got.Config)
	if !ok || wc != gc {
		return "config"
	}
	we, _ := cjsonHash(want.EventLog)
	ge, ok := cjsonHash(got.EventLog)
	if !ok || we != ge {
		return "eventLog"
	}
	return ""
}

// FuzzVerifyEvidence runs VerifyEvidenceJSON on arbitrary bytes. Properties:
// it never panics or errors (deps are valid; a bad bundle is a failed
// report); every report names its failed checks; a passing report means the
// input binds exactly the original evidence (sameEvidence).
func FuzzVerifyEvidence(f *testing.F) {
	e := newFuzzEnv(f)
	orig, err := json.Marshal(e.b)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(orig)
	withRecord := *e.b
	withRecord.Record = &verify.BundleRecord{TxHash: "0x" + strings.Repeat("ee", 32), Method: 1}
	if b, err := json.Marshal(&withRecord); err == nil {
		f.Add(b)
	}
	var generic map[string]any
	if err := json.Unmarshal(orig, &generic); err == nil {
		generic["Customer"] = generic["customer"]
		if b, err := json.Marshal(generic); err == nil {
			f.Add(b)
		}
	}
	if rep, err := verify.VerifyEvidenceJSON(context.Background(), orig, e.deps, e.opts); err != nil || !rep.OK {
		f.Fatalf("the original bundle does not verify: %v\n%s", err, rep.Text())
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rep, err := verify.VerifyEvidenceJSON(context.Background(), raw, e.deps, e.opts)
		if err != nil {
			t.Fatalf("VerifyEvidenceJSON error with valid deps: %v", err)
		}
		if rep.OK != (len(rep.Failed()) == 0) {
			t.Fatalf("report OK=%v with failed checks %v", rep.OK, rep.Failed())
		}
		if _, err := rep.JSON(); err != nil {
			t.Fatalf("report does not encode: %v", err)
		}
		if !rep.OK {
			return
		}
		got, err := verify.ParseBundle(raw)
		if err != nil {
			t.Fatalf("a bundle that does not parse passed: %v", err)
		}
		if d := sameEvidence(e.b, got); d != "" {
			t.Fatalf("a bundle whose %s differs from the attested one passed:\n%s", d, raw)
		}
	})
}

// liveDoc is GET /attest (INTERFACES.md section 11) as a consumer reads it.
type liveDoc struct {
	Quote         string          `json:"quote"`
	EventLog      json.RawMessage `json:"eventLog"`
	Config        json.RawMessage `json:"config"`
	ReleaseIDs    []string        `json:"releaseIds"`
	AppCompose    string          `json:"appCompose"`
	EnclaveSigner string          `json:"enclaveSigner"`
	TLSPubKeyHash string          `json:"tlsPubKeyHash"`
	ReportData    string          `json:"reportData"`
}

// FuzzVerifyLiveSubmission runs VerifyLiveSubmission on arbitrary /attest
// documents for a fixed nonce and served TLS key. A passing report means the
// document binds exactly the original quote, TLS key hash, enclave signer,
// report data, releases, compose, config and RTMR3 events.
func FuzzVerifyLiveSubmission(f *testing.F) {
	e := newFuzzEnv(f)
	nonce := sha256.Sum256([]byte("payer nonce"))
	spki := sha256.Sum256([]byte("served key"))
	docMap := e.w.LiveResponse(nonce, spki)
	orig, err := json.Marshal(docMap)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(orig)
	if ev, err := json.Marshal(docMap["eventLog"]); err == nil {
		alt := map[string]any{}
		for k, v := range docMap {
			alt[k] = v
		}
		alt["eventLog"] = string(ev) // the dstack shape: the log as a JSON string
		if b, err := json.Marshal(alt); err == nil {
			f.Add(b)
		}
	}
	var want liveDoc
	if err := json.Unmarshal(orig, &want); err != nil {
		f.Fatal(err)
	}
	wantRT, ok := runtimeEvents(want.EventLog)
	if !ok {
		f.Fatal("original event log does not replay")
	}
	sub := func(raw []byte) verify.LiveSubmission {
		return verify.LiveSubmission{AttestURL: "https://relay.example/attest", Nonce: nonce, ObservedTLSPubKeyHash: spki, Attest: raw}
	}
	if rep, err := verify.VerifyLiveSubmission(context.Background(), sub(orig), e.deps, e.opts); err != nil || !rep.OK {
		f.Fatalf("the original document does not verify: %v\n%s", err, rep.Text())
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rep, err := verify.VerifyLiveSubmission(context.Background(), sub(raw), e.deps, e.opts)
		if err != nil {
			t.Fatalf("VerifyLiveSubmission error with valid deps: %v", err)
		}
		if rep.OK != (len(rep.Failed()) == 0) {
			t.Fatalf("report OK=%v with failed checks %v", rep.OK, rep.Failed())
		}
		if !rep.OK {
			return
		}
		var got liveDoc
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("a document encoding/json refuses passed: %v", err)
		}
		wq, _ := hexb.Decode(want.Quote, -1)
		gq, qerr := hexb.Decode(got.Quote, -1)
		w32 := func(a, b string) bool { x, ok1 := d32(a); y, ok2 := d32(b); return ok1 && ok2 && x == y }
		ws, _ := d20(want.EnclaveSigner)
		gs, sok := d20(got.EnclaveSigner)
		wr, _ := hexb.Decode(want.ReportData, 64)
		gr, rerr := hexb.Decode(got.ReportData, 64)
		wi, _ := idSet(want.ReleaseIDs)
		gi, iok := idSet(got.ReleaseIDs)
		wc, _ := cjsonHash(want.Config)
		gc, cok := cjsonHash(got.Config)
		gotRT, eok := runtimeEvents(got.EventLog)
		switch {
		case qerr != nil || !bytes.Equal(wq, gq):
			t.Fatalf("a document with another quote passed:\n%s", raw)
		case !w32(want.TLSPubKeyHash, got.TLSPubKeyHash) || !sok || ws != gs || rerr != nil || !bytes.Equal(wr, gr):
			t.Fatalf("a document with another TLS key hash, signer or report data passed:\n%s", raw)
		case !iok || !slices.Equal(wi, gi):
			t.Fatalf("a document with other releases passed:\n%s", raw)
		case want.AppCompose != got.AppCompose:
			t.Fatalf("a document with another compose passed:\n%s", raw)
		case !cok || wc != gc:
			t.Fatalf("a document with another config passed:\n%s", raw)
		case !eok || !sameRuntime(wantRT, gotRT):
			t.Fatalf("a document with other RTMR3 events passed:\n%s", raw)
		}
	})
}

// FuzzPublicAddr: the live attestation dialer (refuseNonPublic) connects to a
// resolved address only if isPublicAddr says it is public. Whatever it calls
// public, sealed-egress's fail-closed classification (policy.Classify, which
// treats only global unicast outside the special ranges as public) must call
// public too: the attest host's DNS answer is the attacker's choice.
func FuzzPublicAddr(f *testing.F) {
	for _, s := range []string{
		"34.1.2.3", "2600:1900::1", "127.0.0.1", "169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe",
		"fd20:ce::254", "100.64.0.1", "fe80::1", "8.8.8.8", "2001:4860::8888",
	} {
		f.Add(netip.MustParseAddr(s).AsSlice())
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, ok := netip.AddrFromSlice(raw)
		if !ok {
			return
		}
		if verify.IsPublicAddr(a.String()) && policy.Classify(a) != policy.ClassPublic {
			t.Fatalf("the live fetch would dial %s, which sealed-egress classifies %s", a, policy.Classify(a))
		}
	})
}
