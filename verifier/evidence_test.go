package verify_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

var (
	testAddrs = chain.Addresses{
		PlatformRegistry:   common.HexToAddress("0x00000000000000000000000000000000000000a1"),
		AppRegistry:        common.HexToAddress("0x00000000000000000000000000000000000000a2"),
		DeploymentRegistry: common.HexToAddress("0x00000000000000000000000000000000000000a3"),
	}
	customer = common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906")
	enclave  = common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9")
	stranger = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
)

type offline struct{}

func (offline) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("offline")
}

func devVerifier(t *testing.T) *attest.Verifier {
	t.Helper()
	v, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: true, Getter: offline{}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type env struct {
	w    *fixture.World
	m    *fixture.MemChain
	b    *verify.Bundle
	deps verify.Deps
	opts verify.Options
}

func newEnv(t *testing.T, debug bool) *env {
	t.Helper()
	return newEnvWith(t, debug, nil)
}

// newEnvWith is newEnv with edit applied to the world before the bundle and the onchain state are built.
func newEnvWith(t *testing.T, debug bool, edit func(w *fixture.World)) *env {
	t.Helper()
	w := fixture.NewWorld(4217, testAddrs, customer, enclave, fixture.SimImageID(debug))
	w.Debug = debug
	if edit != nil {
		edit(w)
	}
	m := fixture.NewMemChain(4217, testAddrs)
	b := w.Bundle(m.Now)
	w.Populate(m, b, true)
	e := &env{
		w: w, m: m, b: b,
		deps: verify.Deps{Quotes: devVerifier(t), Chain: m, Composer: fixture.Composer{}, Now: func() time.Time { return time.Unix(int64(m.Now)+10, 0) }},
		opts: verify.Options{ChainID: 4217, RequireOnchainRecord: true, AcceptSimulated: true},
	}
	// The head block is two seconds old on whatever clock the test sets (D-060 cases override this).
	m.HeadAt = func() time.Time { return e.deps.Now().Add(-2 * time.Second) }
	return e
}

func (e *env) run(t *testing.T) *verify.Report {
	t.Helper()
	rep, err := verify.VerifyEvidence(context.Background(), e.b, e.deps, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

var allEvidenceChecks = []string{
	verify.CheckBundle, verify.CheckChain, verify.CheckQuoteHash, verify.CheckQuote, verify.CheckTDAttributes,
	verify.CheckImageMeasurements, verify.CheckImageApproved, verify.CheckEventLogHash, verify.CheckRTMR3,
	verify.CheckComposeHash, verify.CheckConfigHash, verify.CheckConfigBinding, verify.CheckDeploymentID,
	verify.CheckReportData, verify.CheckReleasesActive, verify.CheckStackRecompute, verify.CheckStackApproved,
	verify.CheckApprovalReleases, verify.CheckOnchainRecord,
}

func TestEvidenceHappyPath(t *testing.T) {
	e := newEnv(t, false)
	rep := e.run(t)
	if !rep.OK {
		t.Fatalf("report failed:\n%s", rep.Text())
	}
	if !rep.Simulated {
		t.Fatal("simulated quote not flagged")
	}
	var names []string
	for _, c := range rep.Checks {
		names = append(names, c.Name)
	}
	for _, want := range allEvidenceChecks {
		if !slices.Contains(names, want) {
			t.Errorf("check %s missing", want)
		}
	}
	if rep.DeploymentID != e.b.DeploymentID || rep.StackHash != e.b.StackHash || rep.RecordDigest == "" || rep.BlockNumber != e.m.Head {
		t.Fatalf("report header %+v", rep)
	}
	text := rep.Text()
	t.Log("\n" + text)
	if !strings.Contains(text, "PASS") || !strings.Contains(text, "WARNING: the quote comes from the dev simulator") || strings.Contains(text, "\u2014") ||
		!strings.Contains(text, "block       100") {
		t.Fatalf("text report:\n%s", text)
	}
	raw, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back verify.Report
	if err := json.Unmarshal(raw, &back); err != nil || !back.OK || !back.Simulated || len(back.Checks) != len(rep.Checks) {
		t.Fatalf("JSON round trip: %v", err)
	}
}

func TestEvidenceJSONEntryPoint(t *testing.T) {
	e := newEnv(t, false)
	raw, err := json.Marshal(e.b)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := verify.VerifyEvidenceJSON(context.Background(), raw, e.deps, e.opts)
	if err != nil || !rep.OK {
		t.Fatalf("%v\n%s", err, rep.Text())
	}
	rep, err = verify.VerifyEvidenceJSON(context.Background(), []byte("{not json"), e.deps, e.opts)
	if err != nil || rep.OK || len(rep.Checks) != 1 || rep.Checks[0].Name != verify.CheckBundle {
		t.Fatalf("bad JSON: %v %+v", err, rep)
	}
	if _, err := verify.VerifyEvidence(context.Background(), e.b, verify.Deps{}, e.opts); err == nil {
		t.Fatal("nil deps accepted")
	}
}

func otherHash(s string) string {
	b, _ := hexb.Decode32(s)
	b[0] ^= 0xff
	return hexb.Enc(b[:])
}

func mustID(s string) [32]byte {
	b, err := hexb.Decode32(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestTamperMatrix changes one thing at a time and requires exactly the right checks to fail.
func TestTamperMatrix(t *testing.T) {
	cases := []struct {
		name   string
		debug  bool
		mutate func(t *testing.T, e *env)
		fail   []string
	}{
		{
			name: "changed config byte",
			mutate: func(t *testing.T, e *env) {
				e.b.Config = json.RawMessage(strings.Replace(string(e.b.Config), "34.1.2.3", "34.1.2.4", 1))
			},
			fail: []string{verify.CheckConfigHash, verify.CheckStackRecompute},
		},
		{
			name: "changed app-compose byte",
			mutate: func(t *testing.T, e *env) {
				e.b.AppCompose = strings.Replace(e.b.AppCompose, `"secure_time":false`, `"secure_time":true `, 1)
			},
			fail: []string{verify.CheckComposeHash, verify.CheckDeploymentID, verify.CheckStackRecompute, verify.CheckStackApproved, verify.CheckApprovalReleases},
		},
		{
			name: "revoked release",
			mutate: func(t *testing.T, e *env) {
				e.m.Releases[e.w.Apps[1].ReleaseID()].Status = chain.ReleaseRevoked
			},
			fail: []string{verify.CheckReleasesActive, verify.CheckStackApproved},
		},
		{
			name: "deprecated release still verifies (D-013)",
			mutate: func(t *testing.T, e *env) {
				e.m.Releases[e.w.Apps[1].ReleaseID()].Status = chain.ReleaseDeprecated
			},
		},
		{
			name: "revoked approval",
			mutate: func(t *testing.T, e *env) {
				e.m.Approvals[customer][mustID(e.b.StackHash)].Revoked = true
			},
			fail: []string{verify.CheckStackApproved},
		},
		{
			name: "expired approval",
			mutate: func(t *testing.T, e *env) {
				e.m.Approvals[customer][mustID(e.b.StackHash)].Expiry = e.m.Now - 1
			},
			fail: []string{verify.CheckStackApproved},
		},
		{
			name:   "debug image",
			debug:  true,
			mutate: func(t *testing.T, e *env) {},
			fail:   []string{verify.CheckTDAttributes, verify.CheckImageApproved, verify.CheckStackApproved},
		},
		{
			name:   "wrong enclave signer",
			mutate: func(t *testing.T, e *env) { e.b.EnclaveSigner = strings.ToLower(stranger.Hex()) },
			fail:   []string{verify.CheckReportData, verify.CheckOnchainRecord},
		},
		{
			name:   "wrong nonce2",
			mutate: func(t *testing.T, e *env) { e.b.Nonce2 = otherHash(e.b.Nonce2) },
			fail:   []string{verify.CheckReportData},
		},
		{
			name:   "quoteHash mismatch",
			mutate: func(t *testing.T, e *env) { e.b.QuoteHash = otherHash(e.b.QuoteHash) },
			fail:   []string{verify.CheckQuoteHash, verify.CheckOnchainRecord},
		},
		{
			name:   "eventLogHash mismatch",
			mutate: func(t *testing.T, e *env) { e.b.EventLogHash = otherHash(e.b.EventLogHash) },
			fail:   []string{verify.CheckEventLogHash, verify.CheckOnchainRecord},
		},
		{
			name: "event log reordered",
			mutate: func(t *testing.T, e *env) {
				var evs []attest.Event
				json.Unmarshal(e.b.EventLog, &evs)
				evs[1], evs[2] = evs[2], evs[1]
				e.b.EventLog, _ = json.Marshal(evs)
				fixture.Rehash(e.b)
			},
			fail: []string{verify.CheckRTMR3, verify.CheckComposeHash, verify.CheckOnchainRecord},
		},
		{
			name: "measurements of another image",
			mutate: func(t *testing.T, e *env) {
				q, _ := hexb.Decode(e.b.Quote, -1)
				parsed, _ := attest.ParseQuote(q, attest.ParseOptions{AllowSimulated: true})
				other := attest.SimMRTDDebug
				e.b.Quote = hexb.Enc(attest.NewSimQuote(attest.SimQuoteParams{RTMR3: parsed.RTMR[3], ReportData: parsed.ReportData, MRTD: &other}))
				fixture.Rehash(e.b)
			},
			fail: []string{verify.CheckImageMeasurements, verify.CheckOnchainRecord},
		},
		{
			name: "approval lists other releases (D-014)",
			mutate: func(t *testing.T, e *env) {
				e.m.Approvals[customer][mustID(e.b.StackHash)].ReleaseIDs = e.w.ReleaseIDs()[:1]
			},
			fail: []string{verify.CheckApprovalReleases},
		},
		{
			name: "approval names another image (D-014)",
			mutate: func(t *testing.T, e *env) {
				other := [32]byte{0x77}
				e.m.Images[other] = fixture.SimImage(false)
				e.m.Approvals[customer][mustID(e.b.StackHash)].ImageID = other
			},
			fail: []string{verify.CheckApprovalReleases},
		},
		{
			name:   "rpc on another chain",
			mutate: func(t *testing.T, e *env) { e.m.ID = 1 },
			fail:   []string{verify.CheckChain},
		},
		{
			name:   "bundle claims another registry",
			mutate: func(t *testing.T, e *env) { e.b.Contracts.DeploymentRegistry = strings.ToLower(stranger.Hex()) },
			fail:   []string{verify.CheckChain},
		},
		{
			name:   "config names another FeeSplitter than the verifier's",
			mutate: func(t *testing.T, e *env) { e.m.Addrs.FeeSplitter = stranger },
			fail:   []string{verify.CheckChain},
		},
		{
			name: "config names the verifier's FeeSplitter",
			mutate: func(t *testing.T, e *env) {
				e.m.Addrs.FeeSplitter = common.HexToAddress("0x0000000000000000000000000000000000000fee")
			},
		},
		{
			name:   "deploymentId not derived from the stack",
			mutate: func(t *testing.T, e *env) { e.b.DeploymentID = otherHash(e.b.DeploymentID) },
			fail:   []string{verify.CheckDeploymentID, verify.CheckOnchainRecord},
		},
		{
			name:   "bundle customer differs from config",
			mutate: func(t *testing.T, e *env) { e.b.Customer = strings.ToLower(stranger.Hex()) },
			fail:   []string{verify.CheckConfigBinding, verify.CheckOnchainRecord},
		},
		{
			name:   "bundle releaseIds differ from config",
			mutate: func(t *testing.T, e *env) { e.b.ReleaseIDs = e.b.ReleaseIDs[:1] },
			fail:   []string{verify.CheckConfigBinding},
		},
		{
			name: "simulated quote on a production verifier",
			mutate: func(t *testing.T, e *env) {
				e.deps.Quotes, _ = attest.NewVerifier(attest.VerifierOptions{Getter: offline{}})
			},
			fail: []string{verify.CheckQuote, verify.CheckTDAttributes, verify.CheckImageMeasurements, verify.CheckRTMR3, verify.CheckComposeHash, verify.CheckReportData},
		},
		{
			name:   "composer not wired",
			mutate: func(t *testing.T, e *env) { e.deps.Composer = nil },
			fail:   []string{verify.CheckStackRecompute},
		},
		{
			name:   "not registered, record required",
			mutate: func(t *testing.T, e *env) { delete(e.m.Deployments, mustID(e.b.DeploymentID)) },
			fail:   []string{verify.CheckOnchainRecord},
		},
		{
			name: "not registered, record not required (oracle pre-registration)",
			mutate: func(t *testing.T, e *env) {
				delete(e.m.Deployments, mustID(e.b.DeploymentID))
				e.opts.RequireOnchainRecord = false
			},
		},
		{
			name:   "closed deployment",
			mutate: func(t *testing.T, e *env) { e.m.Deployments[mustID(e.b.DeploymentID)].Status = chain.DeploymentClosed },
			fail:   []string{verify.CheckOnchainRecord},
		},
		{
			name: "stale evidence",
			mutate: func(t *testing.T, e *env) {
				e.opts.MaxEvidenceAge = 15 * time.Minute
				e.deps.Now = func() time.Time { return time.Unix(int64(e.b.AttestedAt), 0).Add(time.Hour) }
			},
			fail: []string{verify.CheckFreshness},
		},
		{
			name: "fresh evidence",
			mutate: func(t *testing.T, e *env) {
				e.opts.MaxEvidenceAge = 15 * time.Minute
			},
		},
		{
			name: "evidence from the future",
			mutate: func(t *testing.T, e *env) {
				e.opts.MaxEvidenceAge = 15 * time.Minute
				e.deps.Now = func() time.Time { return time.Unix(int64(e.b.AttestedAt), 0).Add(-time.Hour) }
			},
			fail: []string{verify.CheckFreshness},
		},
		{
			name: "expected deployment differs",
			mutate: func(t *testing.T, e *env) {
				other := mustID(otherHash(e.b.DeploymentID))
				e.opts.ExpectedDeploymentID = &other
			},
			fail: []string{verify.CheckDeploymentID},
		},
		{
			name:   "expected customer differs",
			mutate: func(t *testing.T, e *env) { e.opts.ExpectedCustomer = &stranger },
			fail:   []string{verify.CheckExpectedCustomer},
		},
		{
			// attestedAt is in report_data (D-047): an old quote resent with a new attestedAt fails the quote binding
			// and the record.
			name: "old quote resent with a new attestedAt",
			mutate: func(t *testing.T, e *env) {
				e.opts.MaxEvidenceAge = 15 * time.Minute
				e.b.AttestedAt += 3600
				e.deps.Now = func() time.Time { return time.Unix(int64(e.b.AttestedAt)+5, 0) }
			},
			fail: []string{verify.CheckReportData, verify.CheckOnchainRecord},
		},
		{
			// The oracle's first verification runs before registration, so no record vouches for attestedAt. The
			// quote does (D-047): a stale quote relabelled as fresh fails report_data alone.
			name: "unregistered evidence relabelled as fresh (oracle pre-registration)",
			mutate: func(t *testing.T, e *env) {
				delete(e.m.Deployments, mustID(e.b.DeploymentID))
				e.opts.RequireOnchainRecord = false
				e.opts.MaxEvidenceAge = 15 * time.Minute
				e.b.AttestedAt += 3600
				e.deps.Now = func() time.Time { return time.Unix(int64(e.b.AttestedAt)+5, 0) }
			},
			fail: []string{verify.CheckReportData},
		},
		{
			name: "unregistered stale evidence (oracle pre-registration)",
			mutate: func(t *testing.T, e *env) {
				delete(e.m.Deployments, mustID(e.b.DeploymentID))
				e.opts.RequireOnchainRecord = false
				e.opts.MaxEvidenceAge = 15 * time.Minute
				e.deps.Now = func() time.Time { return time.Unix(int64(e.b.AttestedAt), 0).Add(time.Hour) }
			},
			fail: []string{verify.CheckFreshness},
		},
		{
			name:   "expected apps present",
			mutate: func(t *testing.T, e *env) { e.opts.ExpectedAppIDs = []string{e.w.Apps[0].Slug} },
		},
		{
			name:   "expected app missing",
			mutate: func(t *testing.T, e *env) { e.opts.ExpectedAppIDs = []string{"inference-relay"} },
			fail:   []string{verify.CheckExpectedApps},
		},
		{
			name:   "heartbeat that reuses the recorded quote",
			mutate: func(t *testing.T, e *env) { e.opts.Heartbeat = true },
			fail:   []string{verify.CheckOnchainRecord},
		},
		{
			name: "heartbeat with a new quote",
			mutate: func(t *testing.T, e *env) {
				e.opts.Heartbeat = true
				e.w.Nonce2[0] ^= 0xff
				e.b = e.w.Bundle(e.b.AttestedAt + 600)
				e.deps.Now = func() time.Time { return time.Unix(int64(e.b.AttestedAt)+5, 0) }
			},
		},
		{
			name: "heartbeat with a new quote but a stale attestedAt",
			mutate: func(t *testing.T, e *env) {
				e.opts.Heartbeat = true
				e.w.Nonce2[0] ^= 0xff
				e.b = e.w.Bundle(e.b.AttestedAt)
			},
			fail: []string{verify.CheckOnchainRecord},
		},
		{
			name: "heartbeat for an unregistered deployment",
			mutate: func(t *testing.T, e *env) {
				e.opts.Heartbeat = true
				e.opts.RequireOnchainRecord = false
				delete(e.m.Deployments, mustID(e.b.DeploymentID))
			},
			fail: []string{verify.CheckOnchainRecord},
		},
		{
			name: "new evidence without the heartbeat option",
			mutate: func(t *testing.T, e *env) {
				e.w.Nonce2[0] ^= 0xff
				e.b = e.w.Bundle(e.b.AttestedAt + 600)
			},
			fail: []string{verify.CheckOnchainRecord},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.debug)
			tc.mutate(t, e)
			rep := e.run(t)
			got := rep.Failed()
			want := append([]string(nil), tc.fail...)
			sort.Strings(got)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Fatalf("failed checks %v, want %v\n%s", got, want, rep.Text())
			}
			if rep.OK != (len(want) == 0) {
				t.Fatalf("OK = %v", rep.OK)
			}
		})
	}
}

func TestMalformedBundles(t *testing.T) {
	cases := map[string]func(b *verify.Bundle){
		"schema":         func(b *verify.Bundle) { b.Schema = "sealed-evidence/v2" },
		"runtime":        func(b *verify.Bundle) { b.Runtime = "mkosi" },
		"short stack":    func(b *verify.Bundle) { b.StackHash = "0x1234" },
		"bad signer":     func(b *verify.Bundle) { b.EnclaveSigner = "0xzz" },
		"empty quote":    func(b *verify.Bundle) { b.Quote = "0x" },
		"no attestedAt":  func(b *verify.Bundle) { b.AttestedAt = 0 },
		"no event log":   func(b *verify.Bundle) { b.EventLog = nil },
		"bad release id": func(b *verify.Bundle) { b.ReleaseIDs = []string{"0x01"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, false)
			mutate(e.b)
			rep := e.run(t)
			if rep.OK || len(rep.Checks) != 1 || rep.Checks[0].Name != verify.CheckBundle {
				t.Fatalf("%+v", rep)
			}
		})
	}
	t.Run("config key spelled with another case", func(t *testing.T) {
		e := newEnv(t, false)
		// A JSON.parse consumer (the agent) reads "customer"; encoding/json would also read "CUSTOMER".
		e.b.Config = json.RawMessage(strings.Replace(string(e.b.Config), `"customer":`, `"CUSTOMER":"`+strings.ToLower(stranger.Hex())+`","customer":`, 1))
		rep := e.run(t)
		if rep.OK || rep.Check(verify.CheckBundle).OK || !strings.Contains(rep.Check(verify.CheckBundle).Detail, `"CUSTOMER"`) {
			t.Fatalf("case-variant config key accepted:\n%s", rep.Text())
		}
	})
	t.Run("bundle key spelled with another case", func(t *testing.T) {
		e := newEnv(t, false)
		raw, _ := json.Marshal(e.b)
		raw = []byte(strings.Replace(string(raw), `"deploymentId":`, `"DeploymentID":`, 1))
		rep, err := verify.VerifyEvidenceJSON(context.Background(), raw, e.deps, e.opts)
		if err != nil || rep.OK || len(rep.Checks) != 1 || !strings.Contains(rep.Checks[0].Detail, `"deploymentId"`) {
			t.Fatalf("case-variant bundle key: %v %+v", err, rep)
		}
	})
	t.Run("bad config schema", func(t *testing.T) {
		e := newEnv(t, false)
		e.b.Config = json.RawMessage(strings.Replace(string(e.b.Config), "sealed-config/v1", "sealed-config/v0", 1))
		rep := e.run(t)
		if rep.OK || rep.Check(verify.CheckBundle).OK {
			t.Fatal("bad config schema accepted")
		}
	})
}

func TestRPCDownFailsClosed(t *testing.T) {
	e := newEnv(t, false)
	e.m.FailCalls = true
	rep := e.run(t)
	if rep.OK {
		t.Fatal("verification passed with no chain access")
	}
	for _, name := range []string{verify.CheckChain, verify.CheckImageMeasurements, verify.CheckStackApproved, verify.CheckOnchainRecord, verify.CheckReleasesActive} {
		if c := rep.Check(name); c == nil || c.OK {
			t.Errorf("%s passed without chain access", name)
		}
	}
}

func TestDeploymentIDDerivation(t *testing.T) {
	// keccak256(abi.encode(address, bytes32, bytes32)): a left-padded address word, then the two words.
	stack, salt := [32]byte{1}, [32]byte{2}
	enc := append(make([]byte, 12), customer[:]...)
	enc = append(append(enc, stack[:]...), salt[:]...)
	if got := verify.DeploymentID(customer, stack, salt); got != crypto.Keccak256Hash(enc) {
		t.Fatalf("deploymentId %x", got)
	}
}
