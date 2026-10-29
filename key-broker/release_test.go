package keybroker_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/go-tdx-guest/abi"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/attest"
)

// allowedChecks is the pipeline order. customer and config_chain run before stack_recompute, so the cheap checks
// come before the release reads, bundle fetches and the compose. The second chain check pins the approval reads to
// the head again after the bundle fetches (kb-2).
var allowedChecks = []string{
	keybroker.CheckNonce, keybroker.CheckRequest, keybroker.CheckQuote, keybroker.CheckReportData, keybroker.CheckChain, keybroker.CheckImage,
	keybroker.CheckRTMR3, keybroker.CheckComposeHash, keybroker.CheckCustomer, keybroker.CheckConfigChain, keybroker.CheckStackRecompute,
	keybroker.CheckChain, keybroker.CheckStackApproved, keybroker.CheckApprovalReleases, keybroker.CheckSecrets, keybroker.CheckKeys, keybroker.CheckSeal,
}

// hmacKey is HMAC(key, tag || customer || salt) (D-058).
func hmacKey(key []byte, tag string, customer common.Address, salt string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(tag))
	h.Write(customer[:])
	h.Write(common.FromHex(salt))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

func stackSalt(s *kbtest.Stack) string { return s.Config["salt"].(string) }

// TestReleaseHappyPath boots a simulated stack against the registries (in memory and the real contracts on anvil)
// and opens the release like sealed-agent does.
func TestReleaseHappyPath(t *testing.T) {
	for name, mk := range registrars(t) {
		t.Run(name, func(t *testing.T) {
			w := kbtest.NewWorld(t, mk(t))
			h := newHarness(t, w, harnessOpts{})

			notes := w.Compose(t, kbtest.StackOptions{})
			w.Approve(t, notes)
			a := h.attempt(t, notes)
			out := h.release(t, a)
			pt := expectAllowed(t, out, a)

			dep := notes.Result.DeploymentID
			resp := out.Body.(*keybroker.ReleaseResponse)
			if resp.StackHash != notes.Result.StackHash.Hex() || resp.DeploymentID != dep.Hex() {
				t.Fatalf("response %+v, want stack %s deployment %s", resp, notes.Result.StackHash.Hex(), dep.Hex())
			}
			want := map[string]map[string]string{
				"notes": {"APP_SECRET": "notes-app-secret", "DB_PASSWORD": "notes-db-password"},
				"_gate": {"GATE_PASSWORD_BCRYPT": w.GateHash},
			}
			if !mapsEqual(pt.Secrets, want) {
				t.Fatalf("secrets %v, want %v (SMTP_PASSWORD is optional and not stored)", pt.Secrets, want)
			}
			if pt.DiskKey != hmacKey(w.MACKey, "sealed/disk/v2", kbtest.Customer, stackSalt(notes)) ||
				pt.SignerSeed != hmacKey(w.MACKey, "sealed/signer/v2", kbtest.Customer, stackSalt(notes)) {
				t.Fatalf("derived keys differ from HMAC(key, tag || customer || salt)")
			}
			if w.Secrets.Reads("sealed-unrelated-NOT_IN_A_STACK") != 0 {
				t.Fatal("a secret no manifest names was read")
			}

			// The decision log: allowed, every check in order, hashes, names only.
			d := h.log.Last()
			if d == nil || d.Decision != keybroker.DecisionAllowed || !d.Simulated || d.HTTPStatus != 200 {
				t.Fatalf("decision %+v", d)
			}
			var names []string
			for _, c := range d.Checks {
				if !c.OK {
					t.Fatalf("check %s not ok in an allowed decision", c.Name)
				}
				names = append(names, c.Name)
			}
			if !slices.Equal(names, allowedChecks) {
				t.Fatalf("checks %v, want %v", names, allowedChecks)
			}
			hs := d.Hashes
			if hs.StackHash != notes.Result.StackHash.Hex() || hs.ConfigHash != notes.Result.ConfigHash.Hex() || hs.DeploymentID != dep.Hex() ||
				hs.ComposeHash != hs.StackHash || hs.Customer != strings.ToLower(kbtest.Customer.Hex()) || hs.QuoteHash == "" ||
				hs.MeasurementsHash == "" || hs.RTMR3 == "" || hs.Nonce != "0x"+hex.EncodeToString(a.Nonce[:]) || hs.BlockNumber == 0 || hs.BlockTime == 0 ||
				len(hs.ReleaseIDs) != 1 || hs.ImageID != "0x"+hex.EncodeToString(w.SimImage[:]) {
				t.Fatalf("hashes %+v", hs)
			}
			wantReleased := []string{"notes/APP_SECRET", "notes/DB_PASSWORD", "_gate/GATE_PASSWORD_BCRYPT", "diskKey", "signerSeed"}
			if !slices.Equal(d.Released, wantReleased) {
				t.Fatalf("released %v, want %v", d.Released, wantReleased)
			}
			logged, _ := json.Marshal(d)
			for _, secret := range []string{"notes-app-secret", "notes-db-password", w.GateHash, pt.DiskKey[2:], pt.SignerSeed[2:]} {
				if bytes.Contains(logged, []byte(secret)) {
					t.Fatalf("the decision log contains a released value")
				}
			}

			// A reboot of the same deployment gets the same disk key and signer seed (A11).
			a2 := h.attempt(t, notes)
			pt2 := expectAllowed(t, h.release(t, a2), a2)
			if pt2.DiskKey != pt.DiskKey || pt2.SignerSeed != pt.SignerSeed {
				t.Fatal("derived keys changed across boots")
			}

			// A two-app stack releases each app's secrets under its own name. With the same salt it is an upgrade of the
			// same deployment line: another stackHash and deploymentId, the same disk key and enclave signer (D-058).
			both := w.Compose(t, kbtest.StackOptions{Apps: []string{"notes", "llm-gateway"}})
			w.Approve(t, both)
			a3 := h.attempt(t, both)
			out3 := h.release(t, a3)
			pt3 := expectAllowed(t, out3, a3)
			if pt3.Secrets["llm-gateway"]["MASTER_KEY"] != "sk-gateway-master" || pt3.Secrets["notes"]["APP_SECRET"] != "notes-app-secret" {
				t.Fatalf("two-app secrets %v", pt3.Secrets)
			}
			if out3.Body.(*keybroker.ReleaseResponse).DeploymentID == resp.DeploymentID {
				t.Fatal("the upgraded stack has the same deploymentId")
			}
			if pt3.DiskKey != pt.DiskKey || pt3.SignerSeed != pt.SignerSeed {
				t.Fatal("an upgrade with the same salt changed the disk key or the enclave signer")
			}
			// A new salt is a fresh deployment line: a fresh disk and signer.
			fresh := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) { c.Salt = "0x" + strings.Repeat("a5", 32) }})
			w.Approve(t, fresh)
			a4 := h.attempt(t, fresh)
			pt4 := expectAllowed(t, h.release(t, a4), a4)
			if pt4.DiskKey == pt.DiskKey || pt4.SignerSeed == pt.SignerSeed {
				t.Fatal("two salts share a disk key or signer seed")
			}
			// Bundles are fetched once and then served from the content-addressed cache.
			if n := h.bundles.Hits(t, "notes", w.Bundles["notes"].Version()); n != 1 {
				t.Fatalf("notes bundle fetched %d times, want 1", n)
			}
		})
	}
}

func mapsEqual(a, b map[string]map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for n, v := range av {
			if bv[n] != v {
				return false
			}
		}
	}
	return true
}

// restack makes the attempt boot a different app-compose.json consistently: compose-hash event and quote follow it.
func restack(t testing.TB, a *kbtest.Attempt, appCompose string) {
	t.Helper()
	a.AppCompose = appCompose
	a.Events = attest.ExpectedRuntimeEvents(attest.RuntimeParams{AppID: kbtest.InstanceAppID, ComposeHash: sha256.Sum256([]byte(appCompose)), InstanceID: kbtest.InstanceID})
	a.Requote(t, false, nil)
}

func fill(b byte) *attest.Measurement {
	var m attest.Measurement
	for i := range m {
		m[i] = b
	}
	return &m
}

func taggedRD(tag string, fields ...[]byte) attest.ReportData {
	h := sha256.New()
	h.Write([]byte(tag))
	for _, f := range fields {
		h.Write(f)
	}
	var rd attest.ReportData
	copy(rd[:], h.Sum(nil))
	return rd
}

func readTDXQuote(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "tdx", "quotes", name+".dat"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type offlineGetter struct{}

func (offlineGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("offline")
}

// recordedVerifier verifies real quotes offline against recorded Intel collateral, at the recording time.
func recordedVerifier(t testing.TB, name string) *attest.Verifier {
	t.Helper()
	dir := filepath.Join("testdata", "tdx", "pcs", name)
	raw, err := os.ReadFile(filepath.Join(dir, "recorded.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		RecordedAt int64 `json:"recordedAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(meta.RecordedAt, 0)
	g, err := attest.NewCachingGetter(attest.CacheOptions{Dir: dir, TTL: 100 * 365 * 24 * time.Hour, Inner: offlineGetter{}, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewVerifier(attest.VerifierOptions{Getter: g, Now: func() time.Time { return at }, AllowSimulated: true})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type denialCase struct {
	name   string
	status int
	reason string
	check  string // the check that fails
	// opts builds a dedicated harness; nil uses the shared one.
	opts *harnessOpts
	// build returns the request; it may add registry state the case needs.
	build func(t *testing.T, h *harness) *kbtest.Attempt
	// raw replaces the body.
	raw []byte
}

// TestDenials runs every denial reason of INTERFACES.md section 9 (and the malformed-request answers) against the
// in-memory registries and against the real contracts on anvil. Each case asserts the status, the reason and the
// check that failed, so the order of the checks is pinned too.
func TestDenials(t *testing.T) {
	for regName, mk := range registrars(t) {
		t.Run(regName, func(t *testing.T) {
			w := kbtest.NewWorld(t, mk(t))
			base := w.Compose(t, kbtest.StackOptions{})
			w.Approve(t, base)
			shared := newHarness(t, w, harnessOpts{})

			// Registry state for the cases, created once.
			altImage := w.Reg.AddImage(t, "sealed-sim-alt", "1", *fill(0x66), false)
			w.Reg.RevokeImage(t, altImage)
			otherImage := w.Reg.AddImage(t, "sealed-sim-other", "1", *fill(0x88), false)
			unpublished := w.Variant(t, "notes", "1.0.0-sealed.2")
			revocable := w.Variant(t, "notes", "1.0.0-sealed.3")
			w.PublishOnly(t, revocable)
			otherRelease := w.Variant(t, "notes", "1.0.0-sealed.4")
			w.PublishOnly(t, otherRelease)
			junk := []byte("this is not a bundle")
			junkHash := sha256.Sum256(junk)
			junkRelease := w.Reg.PublishRelease(t, "notes", "9.9.9", junkHash)
			for _, b := range []*composer.Bundle{unpublished, revocable, otherRelease} {
				shared.bundles.Put(t, b)
			}
			shared.bundles.Serve(t, "notes", "9.9.9", junk)

			salt := func(b byte) func(c *composer.Config) {
				return func(c *composer.Config) { c.Salt = "0x" + strings.Repeat(hex.EncodeToString([]byte{b}), 32) }
			}
			never := w.Compose(t, kbtest.StackOptions{Edit: salt(0x01)})
			revoked := w.Compose(t, kbtest.StackOptions{Edit: salt(0x02)})
			w.Approve(t, revoked)
			w.Reg.RevokeStack(t, kbtest.Customer, revoked.Result.StackHash)
			withRevocable := w.Compose(t, kbtest.StackOptions{Bundles: map[string]*composer.Bundle{"notes": revocable}})
			w.Approve(t, withRevocable)
			w.Reg.RevokeRelease(t, revocable.ReleaseID)
			otherSet := w.Compose(t, kbtest.StackOptions{Edit: salt(0x03)})
			w.Reg.ApproveStack(t, kbtest.Customer, otherSet.Result.StackHash, [][32]byte{otherRelease.ReleaseID}, w.SimImage)
			otherImg := w.Compose(t, kbtest.StackOptions{Edit: salt(0x04)})
			w.Reg.ApproveStack(t, kbtest.Customer, otherImg.Result.StackHash, otherImg.ReleaseIDs, otherImage)
			cfgOtherImage := w.Compose(t, kbtest.StackOptions{ImageID: otherImage})
			w.Approve(t, cfgOtherImage)
			byOther := w.Compose(t, kbtest.StackOptions{Edit: salt(0x05)})
			w.Reg.ApproveStack(t, kbtest.OtherCustomer, byOther.Result.StackHash, byOther.ReleaseIDs, w.SimImage)
			foreign := w.Compose(t, kbtest.StackOptions{Customer: kbtest.OtherCustomer})
			w.Approve(t, foreign)
			otherChain := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) { c.ChainID++ }})
			w.Approve(t, otherChain)
			otherRegistry := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) {
				c.Contracts.DeploymentRegistry = "0x00000000000000000000000000000000000000d9"
			}})
			w.Approve(t, otherRegistry)
			unpublishedStack := w.Compose(t, kbtest.StackOptions{Bundles: map[string]*composer.Bundle{"notes": unpublished}})
			otherSplitter := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) {
				c.Contracts.FeeSplitter = "0x00000000000000000000000000000000000000f5"
			}})
			w.Approve(t, otherSplitter)
			otherToken := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) { c.FeeToken = "0x20c0000000000000000000000000000000000000" }})
			w.Approve(t, otherToken)

			gce, err := attest.TrimQuote(readTDXQuote(t, "v4_gce_cos113"))
			if err != nil {
				t.Fatal(err)
			}

			const (
				s400 = http.StatusBadRequest
				s403 = http.StatusForbidden
			)
			attempt := func(s *kbtest.Stack) func(t *testing.T, h *harness) *kbtest.Attempt {
				return func(t *testing.T, h *harness) *kbtest.Attempt { return h.attempt(t, s) }
			}
			edit := func(f func(t *testing.T, a *kbtest.Attempt)) func(t *testing.T, h *harness) *kbtest.Attempt {
				return func(t *testing.T, h *harness) *kbtest.Attempt {
					a := h.attempt(t, base)
					f(t, a)
					return a
				}
			}
			cases := []denialCase{
				// nonce
				{name: "nonce never issued", status: s403, reason: keybroker.ReasonBadNonce, check: keybroker.CheckNonce,
					build: func(t *testing.T, h *harness) *kbtest.Attempt { return kbtest.NewAttempt(t, base, randomNonce(t)) }},
				{name: "nonce expired", status: s403, reason: keybroker.ReasonBadNonce, check: keybroker.CheckNonce,
					opts: &harnessOpts{}, // its own clock: moving the shared one would make every later head look stale
					build: func(t *testing.T, h *harness) *kbtest.Attempt {
						a := h.attempt(t, base)
						h.clock.advance(keybroker.NonceLifetime)
						return a
					}},
				{name: "nonce missing", status: s403, reason: keybroker.ReasonBadNonce, check: keybroker.CheckNonce,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Drop = []string{"nonce"} })},
				{name: "nonce malformed", status: s403, reason: keybroker.ReasonBadNonce, check: keybroker.CheckNonce,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Extra = map[string]any{"nonce": "0x1234"} })},
				// malformed requests
				{name: "body is not JSON", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest, raw: []byte("nonce=1")},
				{name: "duplicate key", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest, raw: []byte(`{"nonce":"0x00","nonce":"0x01"}`)},
				{name: "unknown field", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Extra = map[string]any{"secrets": "please"} })},
				{name: "field in another case", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Extra = map[string]any{"ImageId": "0x00"} })},
				{name: "appCompose missing", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Drop = []string{"appCompose"} })},
				{name: "quote field missing", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Drop = []string{"quote"} })},
				// quote
				{name: "no TDX quote (non-confidential VM)", status: s403, reason: keybroker.ReasonQuoteInvalid, check: keybroker.CheckQuote,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Quote = nil })},
				{name: "quote is not a TDX quote", status: s403, reason: keybroker.ReasonQuoteInvalid, check: keybroker.CheckQuote,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Quote = bytes.Repeat([]byte{0x04, 0x00, 0x02, 0x00}, 160) })},
				{name: "simulated quote, production verifier", status: s403, reason: keybroker.ReasonQuoteInvalid, check: keybroker.CheckQuote,
					opts: &harnessOpts{quotes: mustVerifier(t, false)}, build: attempt(base)},
				{name: "simulated quote, broker without AllowSimulated", status: s403, reason: keybroker.ReasonQuoteInvalid, check: keybroker.CheckQuote,
					opts: &harnessOpts{disallowSim: true}, build: attempt(base)},
				{name: "tampered real quote", status: s403, reason: keybroker.ReasonQuoteInvalid, check: keybroker.CheckQuote,
					opts: &harnessOpts{quotes: recordedVerifier(t, "v5_sample")},
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						q := readTDXQuote(t, "v5_sample")
						q[abi.QuoteMinSize/2] ^= 1
						a.Quote = q
					})},
				{name: "real quote with unsigned trailing bytes", status: s403, reason: keybroker.ReasonQuoteInvalid, check: keybroker.CheckQuote,
					opts:  &harnessOpts{quotes: recordedVerifier(t, "v4_gce_cos113")},
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Quote = readTDXQuote(t, "v4_gce_cos113") })},
				{name: "real GCE quote, TCB OutOfDate", status: s403, reason: keybroker.ReasonTCBStatus, check: keybroker.CheckQuote,
					opts:  &harnessOpts{quotes: recordedVerifier(t, "v4_gce_cos113")},
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Quote = gce })},
				// report_data
				{name: "report_data for another ephemeral key", status: s403, reason: keybroker.ReasonReportDataMismatch, check: keybroker.CheckReportData,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						_, other, _ := keybroker.GenerateEphemeralKey()
						a.Quote = kbtest.SimQuoteFor(t, a.Events, attest.KeyReleaseReportData(a.Nonce, other), false, nil)
					})},
				{name: "report_data for another nonce", status: s403, reason: keybroker.ReasonReportDataMismatch, check: keybroker.CheckReportData,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						a.Quote = kbtest.SimQuoteFor(t, a.Events, attest.KeyReleaseReportData(randomNonce(t), a.Pub), false, nil)
					})},
				{name: "evidence quote replayed to the broker", status: s403, reason: keybroker.ReasonReportDataMismatch, check: keybroker.CheckReportData,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						sh, ch := base.Result.StackHash, base.Result.ConfigHash
						rd := taggedRD("sealed/evidence/v1", sh[:], ch[:], make([]byte, 20), a.Nonce[:], make([]byte, 8))
						a.Quote = kbtest.SimQuoteFor(t, a.Events, rd, false, nil)
					})},
				{name: "live attest quote replayed to the broker", status: s403, reason: keybroker.ReasonReportDataMismatch, check: keybroker.CheckReportData,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						rd := taggedRD("sealed/attest/v1", a.Nonce[:], a.Pub[:], make([]byte, 20))
						a.Quote = kbtest.SimQuoteFor(t, a.Events, rd, false, nil)
					})},
				{name: "report_data with a non-zero tail", status: s403, reason: keybroker.ReasonReportDataMismatch, check: keybroker.CheckReportData,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						rd := attest.KeyReleaseReportData(a.Nonce, a.Pub)
						rd[63] = 1
						a.Quote = kbtest.SimQuoteFor(t, a.Events, rd, false, nil)
					})},
				{name: "real UpToDate quote with foreign report_data", status: s403, reason: keybroker.ReasonReportDataMismatch, check: keybroker.CheckReportData,
					opts:  &harnessOpts{quotes: recordedVerifier(t, "v5_sample")},
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Quote = readTDXQuote(t, "v5_sample") })},
				// image
				{name: "image not registered", status: s403, reason: keybroker.ReasonImageNotApproved, check: keybroker.CheckImage,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.ImageID = randomNonce(t) })},
				{name: "image revoked", status: s403, reason: keybroker.ReasonImageNotApproved, check: keybroker.CheckImage,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.ImageID = altImage; a.Requote(t, false, fill(0x66)) })},
				{name: "measurements of another TD", status: s403, reason: keybroker.ReasonMeasurementsMismatch, check: keybroker.CheckImage,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Requote(t, false, fill(0x77)) })},
				{name: "debug TD claims the production image", status: s403, reason: keybroker.ReasonMeasurementsMismatch, check: keybroker.CheckImage,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Requote(t, true, nil) })},
				{name: "debug image", status: s403, reason: keybroker.ReasonImageDebug, check: keybroker.CheckImage,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.ImageID = w.SimDebugImage; a.Requote(t, true, nil) })},
				{name: "TD debug attribute on production measurements", status: s403, reason: keybroker.ReasonImageDebug, check: keybroker.CheckImage,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Requote(t, true, &attest.SimMRTD) })},
				// RTMR3
				{name: "event digest tampered", status: s403, reason: keybroker.ReasonRTMR3Replay, check: keybroker.CheckRTMR3,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Events[4].Digest = strings.Repeat("00", 48) })},
				{name: "event log does not replay to the quote", status: s403, reason: keybroker.ReasonRTMR3Replay, check: keybroker.CheckRTMR3,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						a.Events = attest.ExpectedRuntimeEvents(attest.RuntimeParams{AppID: kbtest.InstanceAppID, ComposeHash: base.Result.StackHash, InstanceID: [20]byte{9}})
					})},
				{name: "extra event after system-ready", status: s403, reason: keybroker.ReasonRTMR3Replay, check: keybroker.CheckRTMR3,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						d := attest.EventDigestV1("extra", nil)
						a.Events = append(a.Events, attest.Event{IMR: 3, EventType: attest.DstackRuntimeEventType, Digest: hex.EncodeToString(d[:]), Event: "extra"})
						a.Requote(t, false, nil)
					})},
				{name: "event missing", status: s403, reason: keybroker.ReasonRTMR3Replay, check: keybroker.CheckRTMR3,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.Events = a.Events[:9]; a.Requote(t, false, nil) })},
				{name: "key provider not tpm", status: s403, reason: keybroker.ReasonRTMR3Replay, check: keybroker.CheckRTMR3,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						p := []byte(`{"name":"none","id":""}`)
						d := attest.EventDigestV1("key-provider", p)
						a.Events[6].EventPayload, a.Events[6].Digest = hex.EncodeToString(p), hex.EncodeToString(d[:])
						a.Requote(t, false, nil)
					})},
				{name: "event log entry with an unknown field", status: s400, reason: keybroker.ReasonBadRequest, check: keybroker.CheckRequest,
					raw: nil, build: func(t *testing.T, h *harness) *kbtest.Attempt {
						a := h.attempt(t, base)
						a.Extra = map[string]any{"eventLog": []any{map[string]any{"imr": 3, "evil": true}}}
						return a
					}},
				// compose
				{name: "compose-hash is not sha256(appCompose)", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckComposeHash,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { a.AppCompose += " " })},
				{name: "booted appCompose differs from the recomputation", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						changed := strings.Replace(a.AppCompose, `"public_logs":false`, `"public_logs":true`, 1)
						if changed == a.AppCompose {
							t.Fatal("public_logs not found in appCompose")
						}
						restack(t, a, changed)
					})},
				{name: "config is not the booted stack's", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						c := maps2(a.Config)
						c["egressAdditions"] = map[string]any{"notes": []any{"exfil.example.com:443"}}
						a.Config = c
					})},
				{name: "config invalid", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: edit(func(t *testing.T, a *kbtest.Attempt) { c := maps2(a.Config); c["bogus"] = "x"; a.Config = c })},
				{name: "config for another composer version", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						c := maps2(a.Config)
						c["composerVersion"] = "0.9.0"
						a.Config = c
					})},
				{name: "releaseIds differ from config", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						a.ReleaseIDs = []string{"0x" + hex.EncodeToString(otherRelease.ReleaseID[:])}
					})},
				{name: "release not published", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: attempt(unpublishedStack)},
				{name: "published bundle is not a bundle", status: s403, reason: keybroker.ReasonComposeMismatch, check: keybroker.CheckStackRecompute,
					build: edit(func(t *testing.T, a *kbtest.Attempt) {
						c := maps2(a.Config)
						c["apps"] = []any{map[string]any{"id": "notes", "releaseId": "0x" + hex.EncodeToString(junkRelease[:])}}
						a.Config = c
						a.ReleaseIDs = []string{"0x" + hex.EncodeToString(junkRelease[:])}
					})},
				{name: "catalog serves other bytes", status: s403, reason: keybroker.ReasonBundleHashMismatch, check: keybroker.CheckStackRecompute,
					opts: &harnessOpts{},
					build: func(t *testing.T, h *harness) *kbtest.Attempt {
						h.bundles.Serve(t, "notes", w.Bundles["notes"].Version(), otherRelease.Tar)
						return h.attempt(t, base)
					}},
				// customer and chain
				{name: "stack of another customer", status: s403, reason: keybroker.ReasonCustomerMismatch, check: keybroker.CheckCustomer, build: attempt(foreign)},
				{name: "config names another chain", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckConfigChain, build: attempt(otherChain)},
				{name: "config names another DeploymentRegistry", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckConfigChain, build: attempt(otherRegistry)},
				{name: "config names another FeeSplitter", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckConfigChain, build: attempt(otherSplitter)},
				{name: "config names another fee token", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckConfigChain, build: attempt(otherToken)},
				{name: "image approved but not in the customer's allowlist", status: s403, reason: keybroker.ReasonImageNotApproved, check: keybroker.CheckImage,
					opts:  &harnessOpts{edit: func(c *keybroker.Config) { c.AllowedImages = [][32]byte{otherImage} }},
					build: attempt(base)},
				// approval
				{name: "never approved", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckStackApproved, build: attempt(never)},
				{name: "approval revoked", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckStackApproved, build: attempt(revoked)},
				{name: "release revoked after approval", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckStackApproved, build: attempt(withRevocable)},
				{name: "approved by another customer only", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckStackApproved, build: attempt(byOther)},
				{name: "approval names other releases", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckApprovalReleases, build: attempt(otherSet)},
				{name: "approval names another image", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckApprovalReleases, build: attempt(otherImg)},
				{name: "request imageId is not config.imageId", status: s403, reason: keybroker.ReasonStackNotApproved, check: keybroker.CheckApprovalReleases,
					build: func(t *testing.T, h *harness) *kbtest.Attempt {
						a := h.attempt(t, cfgOtherImage)
						a.ImageID = w.SimImage // the quote's measurements are sealed-sim's
						return a
					}},
			}
			seen := map[string]bool{}
			for _, tc := range cases {
				seen[tc.reason] = true
				t.Run(tc.name, func(t *testing.T) {
					h := shared
					if tc.opts != nil {
						h = newHarness(t, w, *tc.opts)
						for _, b := range []*composer.Bundle{unpublished, revocable, otherRelease} {
							h.bundles.Put(t, b)
						}
					}
					var out *keybroker.Outcome
					if tc.raw != nil {
						out = h.b.Release(context.Background(), tc.raw, "")
						h.flush(t)
					} else {
						out = h.release(t, tc.build(t, h))
					}
					d := expectDenied(t, out, tc.status, tc.reason)
					t.Logf("%d %s: %s", out.Status, d.Reason, d.Detail)
					checks := out.Decision.Checks
					last := checks[len(checks)-1]
					if last.OK || last.Name != tc.check || last.Reason != tc.reason {
						t.Fatalf("failing check %+v, want %s (%s)", last, tc.check, d.Detail)
					}
					for _, c := range checks[:len(checks)-1] {
						if !c.OK {
							t.Fatalf("check %s failed before %s", c.Name, tc.check)
						}
					}
					if out.Decision.Released != nil {
						t.Fatal("a denied decision lists released secrets")
					}
					if h.log.Last() == nil || h.log.Last().RequestID != out.Decision.RequestID {
						t.Fatal("the denial was not written to the decision log")
					}
				})
			}
			for _, r := range keybroker.DenialReasons {
				if !seen[r] {
					t.Errorf("no case for reason %s", r)
				}
			}
		})
	}
}

func maps2(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func mustVerifier(t testing.TB, allowSim bool) *attest.Verifier {
	t.Helper()
	v, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: allowSim})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestNonceReplay: a nonce releases at most once, also when the same request races.
func TestNonceReplay(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	h := newHarness(t, w, harnessOpts{})
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)

	a := h.attempt(t, s)
	body := a.Body(t)
	expectAllowed(t, h.b.Release(context.Background(), body, ""), a)
	expectDenied(t, h.b.Release(context.Background(), body, ""), http.StatusForbidden, keybroker.ReasonBadNonce)

	// A denied attempt burns its nonce too: the corrected request with the same nonce is refused.
	a2 := h.attempt(t, s)
	good := a2.Body(t)
	a2.ImageID = randomNonce(t)
	expectDenied(t, h.b.Release(context.Background(), a2.Body(t), ""), http.StatusForbidden, keybroker.ReasonImageNotApproved)
	expectDenied(t, h.b.Release(context.Background(), good, ""), http.StatusForbidden, keybroker.ReasonBadNonce)

	// 32 concurrent copies of one request: exactly one is released.
	a3 := h.attempt(t, s)
	body3 := a3.Body(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	for range 32 {
		wg.Go(func() {
			out := h.b.Release(context.Background(), body3, "")
			mu.Lock()
			statuses[out.Status]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if statuses[http.StatusOK] != 1 || statuses[http.StatusForbidden] != 31 {
		t.Fatalf("statuses %v, want one 200 and 31 403", statuses)
	}
}

// failingMAC is a KMS outage.
type failingMAC struct{}

func (failingMAC) MAC(context.Context, []byte) ([]byte, error) { return nil, errors.New("kms down") }

// TestUnavailable: dependency failures and missing secrets answer 503 (the agent retries) and release nothing.
func TestUnavailable(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	const s503 = http.StatusServiceUnavailable

	run := func(t *testing.T, o harnessOpts, prep func(h *harness)) *keybroker.Outcome {
		h := newHarness(t, w, o)
		if prep != nil {
			prep(h)
		}
		return h.release(t, h.attempt(t, s))
	}
	secretsWith := func(edit func(m *keybroker.MemorySecretStore)) keybroker.SecretStore {
		m := keybroker.NewMemorySecretStore(map[string]string{
			"sealed-notes-APP_SECRET": "a", "sealed-notes-DB_PASSWORD": "b", keybroker.GateSecretID: w.GateHash,
		})
		edit(m)
		return m
	}

	t.Run("required secret missing", func(t *testing.T) {
		out := run(t, harnessOpts{secrets: secretsWith(func(m *keybroker.MemorySecretStore) { m.Delete("sealed-notes-DB_PASSWORD") })}, nil)
		d := expectDenied(t, out, s503, keybroker.ReasonSecretMissing)
		if !strings.Contains(d.Detail, "notes/DB_PASSWORD") || !strings.Contains(d.Detail, "sealed-notes-DB_PASSWORD") {
			t.Fatalf("detail %q", d.Detail)
		}
	})
	t.Run("gate password missing", func(t *testing.T) {
		out := run(t, harnessOpts{secrets: secretsWith(func(m *keybroker.MemorySecretStore) { m.Delete(keybroker.GateSecretID) })}, nil)
		expectDenied(t, out, s503, keybroker.ReasonSecretMissing)
	})
	t.Run("gate secret holds a plain password", func(t *testing.T) {
		out := run(t, harnessOpts{secrets: secretsWith(func(m *keybroker.MemorySecretStore) { m.Set(keybroker.GateSecretID, kbtest.GatePassword) })}, nil)
		expectDenied(t, out, s503, keybroker.ReasonSecretInvalid)
	})
	t.Run("secret is not UTF-8", func(t *testing.T) {
		out := run(t, harnessOpts{secrets: secretsWith(func(m *keybroker.MemorySecretStore) { m.Set("sealed-notes-APP_SECRET", "\xff\xfe") })}, nil)
		expectDenied(t, out, s503, keybroker.ReasonSecretInvalid)
	})
	t.Run("Secret Manager down", func(t *testing.T) {
		out := run(t, harnessOpts{secrets: secretsWith(func(m *keybroker.MemorySecretStore) { m.Fail = errors.New("503 from secretmanager") })}, nil)
		expectDenied(t, out, s503, keybroker.ReasonUnavailable)
	})
	t.Run("KMS down", func(t *testing.T) {
		expectDenied(t, run(t, harnessOpts{mac: failingMAC{}}, nil), s503, keybroker.ReasonUnavailable)
	})
	t.Run("catalog down", func(t *testing.T) {
		out := run(t, harnessOpts{}, func(h *harness) { h.bundles.Down = true })
		expectDenied(t, out, s503, keybroker.ReasonUnavailable)
	})
	t.Run("RPC down", func(t *testing.T) {
		mc := kbtest.NewMemChain(kbtest.MemChainID)
		mc.FailReads = errors.New("connection refused")
		out := run(t, harnessOpts{chain: mc}, nil)
		expectDenied(t, out, s503, keybroker.ReasonUnavailable)
	})
	t.Run("RPC serves another chain", func(t *testing.T) {
		out := run(t, harnessOpts{chain: kbtest.NewMemChain(1)}, nil)
		d := expectDenied(t, out, s503, keybroker.ReasonChainStale)
		if !strings.Contains(d.Detail, "chain 1") || out.RetryAfter == 0 {
			t.Fatalf("detail %q retry %d", d.Detail, out.RetryAfter)
		}
	})
	t.Run("decision log down: an allowed release is withheld", func(t *testing.T) {
		out := run(t, harnessOpts{log: &keybroker.MemoryLog{Fail: errors.New("logging unavailable")}}, nil)
		expectDenied(t, out, s503, keybroker.ReasonLogFailed)
		if out.Decision.Released != nil {
			t.Fatal("released list kept")
		}
	})
	t.Run("decision log down: a denial still answers 403", func(t *testing.T) {
		h := newHarness(t, w, harnessOpts{log: &keybroker.MemoryLog{Fail: errors.New("logging unavailable")}})
		a := h.attempt(t, s)
		a.Quote = nil
		expectDenied(t, h.release(t, a), http.StatusForbidden, keybroker.ReasonQuoteInvalid)
	})
}

// TestReleaseDeadline: a release that cannot finish in time answers 503, not a denial.
func TestReleaseDeadline(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	h := newHarness(t, w, harnessOpts{quotes: slowVerifier{d: time.Second}})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	out := h.b.Release(ctx, h.attempt(t, s).Body(t), "")
	expectDenied(t, out, http.StatusServiceUnavailable, keybroker.ReasonUnavailable)
	h.flush(t)
	if h.log.Last() == nil {
		t.Fatal("decision not logged after the deadline")
	}
}

type slowVerifier struct{ d time.Duration }

func (s slowVerifier) VerifyQuote(ctx context.Context, raw []byte) (*attest.QuoteResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(s.d):
		return nil, attest.ErrQuoteInvalid
	}
}

// TestBrokerConfigValidation: the broker refuses to start without its bootstrap settings and backends.
func TestBrokerConfigValidation(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	h := newHarness(t, w, harnessOpts{})
	good := h.b.Config()
	deps := keybroker.Deps{Nonces: keybroker.NewNonceStore(keybroker.NonceOptions{}), Quotes: simVerifier(t), Chain: w.Reg.Chain(),
		Bundles: w.Source, Secrets: w.Secrets, MAC: failingMAC{}, Log: &keybroker.MemoryLog{}}
	for name, mutate := range map[string]func(c *keybroker.Config, d *keybroker.Deps){
		"no customer":     func(c *keybroker.Config, d *keybroker.Deps) { c.Customer = common.Address{} },
		"no chain id":     func(c *keybroker.Config, d *keybroker.Deps) { c.ChainID = 0 },
		"no registry":     func(c *keybroker.Config, d *keybroker.Deps) { c.Contracts.AppRegistry = common.Address{} },
		"no log":          func(c *keybroker.Config, d *keybroker.Deps) { d.Log = nil },
		"no nonces":       func(c *keybroker.Config, d *keybroker.Deps) { d.Nonces = nil },
		"no verifier":     func(c *keybroker.Config, d *keybroker.Deps) { d.Quotes = nil },
		"no KMS":          func(c *keybroker.Config, d *keybroker.Deps) { d.MAC = nil },
		"no secrets":      func(c *keybroker.Config, d *keybroker.Deps) { d.Secrets = nil },
		"no bundles":      func(c *keybroker.Config, d *keybroker.Deps) { d.Bundles = nil },
		"no rpc chain":    func(c *keybroker.Config, d *keybroker.Deps) { d.Chain = nil },
		"no fee splitter": func(c *keybroker.Config, d *keybroker.Deps) { c.FeeSplitter = common.Address{} },
		"no fee token":    func(c *keybroker.Config, d *keybroker.Deps) { c.FeeToken = common.Address{} },
		"simulated quotes on mainnet": func(c *keybroker.Config, d *keybroker.Deps) {
			c.ChainID, c.AllowSimulated = keybroker.MainnetChainID, true
		},
		"head age over 5 minutes": func(c *keybroker.Config, d *keybroker.Deps) { c.MaxHeadAge = 301 * time.Second },
		"negative head age":       func(c *keybroker.Config, d *keybroker.Deps) { c.MaxHeadAge = -time.Second },
	} {
		c, d := good, deps
		mutate(&c, &d)
		if _, err := keybroker.New(c, d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := keybroker.New(good, deps); err != nil {
		t.Fatal(err)
	}
}
