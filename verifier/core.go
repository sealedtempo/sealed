package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// chainCallTimeout bounds each RPC read.
const chainCallTimeout = 20 * time.Second

// session carries the state shared by the checks of one verification. Every check records exactly one entry in
// the report; a check whose inputs are unavailable fails with the reason instead of being skipped.
type session struct {
	ctx   context.Context
	deps  Deps
	opts  Options
	rep   *Report
	chain ChainReader // deps.Chain, pinned to one block by checkChain when the reader supports it

	quote      *attest.Quote
	runtime    *attest.RuntimeInfo
	cfgRaw     json.RawMessage
	cfg        *parsedConfig
	configHash [32]byte // sha256(CJSON(config)), computed
	appCompose []byte
	stackHash  [32]byte // sha256(appCompose), computed
	releases   []*chain.Release
}

func (s *session) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.ctx, chainCallTimeout)
}

func hex0x(b []byte) string { return hexb.Enc(b) }

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// checkChain requires the RPC, the bundle and the config to agree on the chain and on the registry addresses the
// verifier is configured with (it never reads addresses from the bundle).
func (s *session) checkChain(claimedChainID uint64, claimed *BundleContracts) {
	ctx, cancel := s.callCtx()
	defer cancel()
	rpcID, err := s.deps.Chain.ChainID(ctx)
	if err != nil {
		s.rep.failf(CheckChain, "eth_chainId: %v", err)
		return
	}
	data := map[string]any{"rpcChainId": rpcID}
	var problems []string
	if pinned, block, ok, err := pinHead(ctx, s.deps.Chain); ok {
		if err != nil {
			problems = append(problems, fmt.Sprintf("eth_blockNumber: %v", err))
		} else {
			s.chain = pinned
			s.rep.BlockNumber = block
			data["blockNumber"] = block
		}
	}
	if s.opts.ChainID != 0 && rpcID != s.opts.ChainID {
		problems = append(problems, fmt.Sprintf("RPC is chain %d, verifier expects %d", rpcID, s.opts.ChainID))
	}
	if claimedChainID != 0 && claimedChainID != rpcID {
		problems = append(problems, fmt.Sprintf("bundle is for chain %d, RPC is chain %d", claimedChainID, rpcID))
	}
	if s.cfg != nil && s.cfg.ChainID != rpcID {
		problems = append(problems, fmt.Sprintf("config.chainId %d, RPC is chain %d", s.cfg.ChainID, rpcID))
	}
	want := s.deps.Chain.Addresses()
	compare := func(what, got string, addr common.Address) {
		if got == "" {
			return
		}
		a, err := parseAddress(got)
		if err != nil || a != addr {
			problems = append(problems, fmt.Sprintf("%s %s, verifier uses %s", what, got, addr.Hex()))
		}
	}
	if claimed != nil {
		compare("bundle platformRegistry", claimed.PlatformRegistry, want.PlatformRegistry)
		compare("bundle appRegistry", claimed.AppRegistry, want.AppRegistry)
		compare("bundle deploymentRegistry", claimed.DeploymentRegistry, want.DeploymentRegistry)
	}
	if s.cfg != nil {
		compare("config platformRegistry", s.cfg.Contracts.PlatformRegistry, want.PlatformRegistry)
		compare("config appRegistry", s.cfg.Contracts.AppRegistry, want.AppRegistry)
		compare("config deploymentRegistry", s.cfg.Contracts.DeploymentRegistry, want.DeploymentRegistry)
	}
	data["deploymentRegistry"] = want.DeploymentRegistry.Hex()
	if len(problems) > 0 {
		s.rep.fail(CheckChain, joinProblems(problems), data)
		return
	}
	at := "latest block"
	if s.rep.BlockNumber != 0 {
		at = fmt.Sprintf("block %d", s.rep.BlockNumber)
	}
	s.rep.pass(CheckChain, fmt.Sprintf("chain %d, registries match, reads at %s", rpcID, at), data)
}

// checkQuote verifies the quote (signature chain, collateral, TCB policy) and its TD attributes.
func (s *session) checkQuote(raw []byte) {
	res, err := s.deps.Quotes.VerifyQuote(s.ctx, raw)
	if err != nil {
		s.rep.fail(CheckQuote, err.Error(), nil)
		// Keep parsing for diagnostics in the following checks; the report already fails.
		if q, perr := s.deps.Quotes.ParseQuote(raw); perr == nil {
			s.quote = q
		}
	} else {
		s.quote = res.Quote
		data := map[string]any{"tcbStatus": res.TCBStatus, "qeTcbStatus": res.QETCBStatus, "simulated": res.Simulated}
		if res.Simulated {
			s.rep.Simulated = true
			s.rep.pass(CheckQuote, "simulated quote accepted by a dev verifier (AllowSimulated); no hardware attestation", data)
		} else {
			data["quoteVersion"] = res.Quote.Version
			data["fmspc"] = res.FMSPC
			data["platformTcbStatus"] = res.PlatformTCBStatus
			data["tcbDate"] = res.TCBDate
			if res.ModuleTCBStatus != "" {
				data["moduleTcbStatus"] = res.ModuleTCBStatus
				data["moduleTcbDate"] = res.ModuleTCBDate
			}
			data["advisoryIds"] = res.AdvisoryIDs
			s.rep.pass(CheckQuote, fmt.Sprintf("TDX quote v%d verified with Intel collateral, TCB %s (platform %s, module %s), QE %s",
				res.Quote.Version, res.TCBStatus, res.PlatformTCBStatus, orNone(res.ModuleTCBStatus), res.QETCBStatus), data)
		}
	}
	if s.quote == nil {
		s.rep.fail(CheckTDAttributes, "no parsable quote", nil)
		return
	}
	if s.quote.Simulated {
		s.rep.Simulated = true
	}
	data := map[string]any{"tdAttributes": hex0x(s.quote.TDAttributes[:]), "xfam": hex0x(s.quote.XFAM[:])}
	if err := s.quote.CheckProductionAttributes(); err != nil {
		s.rep.fail(CheckTDAttributes, err.Error(), data)
		return
	}
	s.rep.pass(CheckTDAttributes, "production TD: no debug bits, not migratable, SEPT_VE_DISABLE set, no reserved bits", data)
}

// checkImage compares the quote's measurements with PlatformRegistry and requires an approved non-debug image.
func (s *session) checkImage(imageID [32]byte) {
	ctx, cancel := s.callCtx()
	defer cancel()
	img, err := s.chain.GetImage(ctx, imageID)
	if err != nil {
		s.rep.failf(CheckImageMeasurements, "PlatformRegistry.getImage(%s): %v", hex0x(imageID[:]), err)
		s.rep.failf(CheckImageApproved, "image %s unavailable", hex0x(imageID[:]))
		return
	}
	data := map[string]any{"imageId": hex0x(imageID[:]), "name": img.Name, "version": img.Version, "onchain": hex0x(img.MeasurementsHash[:])}
	switch {
	case s.quote == nil:
		s.rep.fail(CheckImageMeasurements, "no parsable quote", data)
	case s.quote.MeasurementsHash() != img.MeasurementsHash:
		got := s.quote.MeasurementsHash()
		data["quote"] = hex0x(got[:])
		s.rep.fail(CheckImageMeasurements, fmt.Sprintf("keccak256(mrtd||rtmr0||rtmr1||rtmr2) = %s, PlatformRegistry has %s", hex0x(got[:]), hex0x(img.MeasurementsHash[:])), data)
	default:
		s.rep.pass(CheckImageMeasurements, fmt.Sprintf("measurements match image %s %s", img.Name, img.Version), data)
	}

	approved, err := s.chain.IsApprovedImage(ctx, imageID)
	data = map[string]any{"imageId": hex0x(imageID[:]), "isDebug": img.IsDebug, "status": img.Status}
	switch {
	case err != nil:
		s.rep.failf(CheckImageApproved, "PlatformRegistry.isApprovedImage: %v", err)
	case img.IsDebug:
		s.rep.fail(CheckImageApproved, fmt.Sprintf("image %s %s is a debug image", img.Name, img.Version), data)
	case !approved:
		s.rep.fail(CheckImageApproved, fmt.Sprintf("image %s %s is not approved (status %d)", img.Name, img.Version, img.Status), data)
	default:
		s.rep.pass(CheckImageApproved, "isApprovedImage: active, not debug", data)
	}
}

// checkEventLog parses the event log and replays RTMR3 with the exact expected sequence.
func (s *session) checkEventLog(raw json.RawMessage) {
	if s.quote == nil {
		s.rep.fail(CheckRTMR3, "no parsable quote", nil)
		return
	}
	evs, err := attest.ParseEventLog(raw)
	if err != nil {
		s.rep.fail(CheckRTMR3, err.Error(), nil)
		return
	}
	info, err := attest.CheckRuntimeEvents(evs, s.quote.RTMR[3])
	if err != nil {
		s.rep.fail(CheckRTMR3, err.Error(), map[string]any{"quoteRtmr3": hex0x(s.quote.RTMR[3][:])})
		return
	}
	s.runtime = info
	s.rep.pass(CheckRTMR3, "event log replays to the quote's RTMR3 with the exact Sealed event sequence", map[string]any{
		"rtmr3": hex0x(info.RTMR3[:]), "composeHash": hex0x(info.ComposeHash[:]), "keyProvider": info.KeyProvider,
		"storageFs": info.StorageFS, "storageEncrypted": info.StorageEncrypted,
	})
}

// checkComposeHash requires compose-hash (RTMR3) == sha256(appCompose) [== claimed stackHash].
func (s *session) checkComposeHash(claimed *[32]byte) {
	data := map[string]any{"sha256(appCompose)": hex0x(s.stackHash[:])}
	var problems []string
	if s.runtime == nil {
		problems = append(problems, "no verified compose-hash event")
	} else if s.runtime.ComposeHash != s.stackHash {
		problems = append(problems, fmt.Sprintf("compose-hash event %s != sha256(appCompose) %s", hex0x(s.runtime.ComposeHash[:]), hex0x(s.stackHash[:])))
	}
	if claimed != nil && *claimed != s.stackHash {
		problems = append(problems, fmt.Sprintf("stackHash %s != sha256(appCompose) %s", hex0x(claimed[:]), hex0x(s.stackHash[:])))
	}
	if len(problems) > 0 {
		s.rep.fail(CheckComposeHash, joinProblems(problems), data)
		return
	}
	s.rep.pass(CheckComposeHash, "compose-hash = sha256(appCompose) = stackHash", data)
}

// computeConfigHash canonicalizes the config. It returns false (and records config_hash as failed) on error.
func (s *session) computeConfigHash() bool {
	canon, err := cjson.Canonicalize(s.cfgRaw)
	if err != nil {
		s.rep.failf(CheckConfigHash, "config is not canonicalizable: %v", err)
		return false
	}
	s.configHash = sha256.Sum256(canon)
	return true
}

// checkReleases reads each release of config.apps and requires it to be active and to belong to that app.
func (s *session) checkReleases() {
	if s.cfg == nil {
		s.rep.fail(CheckReleasesActive, "no config", nil)
		return
	}
	ctx, cancel := s.callCtx()
	defer cancel()
	s.releases = make([]*chain.Release, len(s.cfg.releaseIDs))
	var problems []string
	var list []map[string]any
	for i, id := range s.cfg.releaseIDs {
		app := s.cfg.Apps[i].ID
		rel, err := s.chain.GetRelease(ctx, id)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s release %s: %v", app, hex0x(id[:]), err))
			continue
		}
		s.releases[i] = rel
		active, err := s.chain.IsActiveRelease(ctx, id)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s isActiveRelease: %v", app, err))
			continue
		}
		list = append(list, map[string]any{"app": app, "releaseId": hex0x(id[:]), "version": rel.Version, "bundleHash": hex0x(rel.BundleHash[:]), "status": rel.Status, "active": active})
		if !active {
			problems = append(problems, fmt.Sprintf("%s %s release %s is not active (status %d)", app, rel.Version, hex0x(id[:]), rel.Status))
		}
		if want := crypto.Keccak256Hash([]byte(app)); rel.AppId != want {
			problems = append(problems, fmt.Sprintf("release %s belongs to app %s, not %q", hex0x(id[:]), hex0x(rel.AppId[:]), app))
		}
	}
	data := map[string]any{"releases": list}
	if len(problems) > 0 {
		s.rep.fail(CheckReleasesActive, joinProblems(problems), data)
		return
	}
	s.rep.pass(CheckReleasesActive, fmt.Sprintf("%d releases active", len(list)), data)
}

// checkRecompute recomputes appCompose from the config and the onchain releases and requires byte equality.
func (s *session) checkRecompute(deploymentID [32]byte) {
	if s.deps.Composer == nil {
		s.rep.fail(CheckStackRecompute, ErrComposerNotConfigured.Error()+": the stack cannot be recomputed, so it is not verified", nil)
		return
	}
	if s.cfg == nil || s.releases == nil || slices.Contains(s.releases, nil) {
		s.rep.fail(CheckStackRecompute, "releases unavailable", nil)
		return
	}
	in := ComposeInput{Config: s.cfgRaw}
	for i, rel := range s.releases {
		in.Releases = append(in.Releases, ComposeRelease{App: s.cfg.Apps[i].ID, ReleaseID: s.cfg.releaseIDs[i], AppID: rel.AppId, Version: rel.Version, BundleHash: rel.BundleHash})
	}
	out, err := s.deps.Composer.Compose(s.ctx, in)
	if err != nil {
		s.rep.failf(CheckStackRecompute, "composer: %v", err)
		return
	}
	data := map[string]any{"recomputedStackHash": hex0x(out.StackHash[:])}
	var problems []string
	if !bytes.Equal(out.AppCompose, s.appCompose) {
		problems = append(problems, fmt.Sprintf("recomputed app-compose.json differs from the attested one (%d vs %d bytes, first difference at byte %d)", len(out.AppCompose), len(s.appCompose), firstDiff(out.AppCompose, s.appCompose)))
	}
	if sum := sha256.Sum256(out.AppCompose); out.StackHash != sum {
		problems = append(problems, "composer stackHash is not sha256 of its appCompose")
	}
	if out.StackHash != s.stackHash {
		problems = append(problems, fmt.Sprintf("recomputed stackHash %s != %s", hex0x(out.StackHash[:]), hex0x(s.stackHash[:])))
	}
	if out.ConfigHash != s.configHash {
		problems = append(problems, fmt.Sprintf("composer configHash %s != %s", hex0x(out.ConfigHash[:]), hex0x(s.configHash[:])))
	}
	if out.DeploymentID != deploymentID {
		problems = append(problems, fmt.Sprintf("composer deploymentId %s != %s", hex0x(out.DeploymentID[:]), hex0x(deploymentID[:])))
	}
	if len(problems) > 0 {
		s.rep.fail(CheckStackRecompute, joinProblems(problems), data)
		return
	}
	s.rep.pass(CheckStackRecompute, "app-compose.json recomputed byte for byte from config and onchain releases", data)
}

// checkApproval requires DeploymentRegistry.isStackApproved and the approval's release set and image to equal the
// config's (D-014).
func (s *session) checkApproval() {
	if s.cfg == nil {
		s.rep.fail(CheckStackApproved, "no config", nil)
		s.rep.fail(CheckApprovalReleases, "no config", nil)
		return
	}
	ctx, cancel := s.callCtx()
	defer cancel()
	customer := s.cfg.customer
	data := map[string]any{"customer": customer.Hex(), "stackHash": hex0x(s.stackHash[:])}
	ok, err := s.chain.IsStackApproved(ctx, customer, s.stackHash)
	switch {
	case err != nil:
		s.rep.failf(CheckStackApproved, "isStackApproved: %v", err)
	case !ok:
		s.rep.fail(CheckStackApproved, "the customer's approval of this stack is missing, revoked or expired, or one of its releases or its image is no longer active", data)
	default:
		s.rep.pass(CheckStackApproved, "isStackApproved(customer, stackHash)", data)
	}

	ap, err := s.chain.GetStackApproval(ctx, customer, s.stackHash)
	if err != nil {
		s.rep.failf(CheckApprovalReleases, "getStackApproval: %v", err)
		return
	}
	data = map[string]any{"approvedAt": ap.ApprovedAt, "expiry": ap.Expiry, "revoked": ap.Revoked, "imageId": hex0x(ap.ImageID[:])}
	var problems []string
	if ap.ApprovedAt == 0 {
		problems = append(problems, "no approval stored for (customer, stackHash)")
	} else {
		if !sameIDSet(ap.ReleaseIDs, s.cfg.releaseIDs) {
			problems = append(problems, fmt.Sprintf("approved releases %s != config releases %s", idList(ap.ReleaseIDs), idList(s.cfg.releaseIDs)))
		}
		if ap.ImageID != s.cfg.imageID {
			problems = append(problems, fmt.Sprintf("approved image %s != config.imageId %s", hex0x(ap.ImageID[:]), hex0x(s.cfg.imageID[:])))
		}
	}
	if len(problems) > 0 {
		s.rep.fail(CheckApprovalReleases, joinProblems(problems), data)
		return
	}
	s.rep.pass(CheckApprovalReleases, "approval names exactly the config's releases and image", data)
}

// recordExpectation is what the onchain record must hold.
type recordExpectation struct {
	deploymentID  [32]byte
	customer      common.Address
	stackHash     [32]byte
	imageID       [32]byte
	configHash    [32]byte
	enclaveSigner common.Address
	// Evidence mode also binds the exact quote, its attestedAt and the event log; live mode has a fresh quote.
	quoteHash    *[32]byte
	attestedAt   *uint64
	eventLogHash *[32]byte
	// eventLogHashInfo is compared for information only (live mode).
	eventLogHashInfo *[32]byte
}

func (s *session) checkRecord(want recordExpectation) {
	ctx, cancel := s.callCtx()
	defer cancel()
	d, err := s.chain.GetDeployment(ctx, want.deploymentID)
	if errors.Is(err, chain.ErrNotFound) {
		if s.opts.Heartbeat {
			s.rep.failf(CheckOnchainRecord, "heartbeat for deployment %s, which is not registered", hex0x(want.deploymentID[:]))
		} else if s.opts.RequireOnchainRecord {
			s.rep.failf(CheckOnchainRecord, "deployment %s is not registered in DeploymentRegistry", hex0x(want.deploymentID[:]))
		} else {
			s.rep.pass(CheckOnchainRecord, "deployment not registered yet (not required by this verification)", map[string]any{"registered": false})
		}
		return
	}
	if err != nil {
		s.rep.failf(CheckOnchainRecord, "getDeployment: %v", err)
		return
	}
	data := map[string]any{"registered": true, "status": d.Status, "attestedAt": d.AttestedAt, "lastAttestedAt": d.LastAttestedAt, "method": d.Method, "registeredAt": d.RegisteredAt}
	var problems []string
	if d.Status != chain.DeploymentActive {
		problems = append(problems, fmt.Sprintf("deployment status %d is not Active", d.Status))
	}
	cmp32 := func(name string, got, exp [32]byte) {
		if got != exp {
			problems = append(problems, fmt.Sprintf("%s onchain %s != %s", name, hex0x(got[:]), hex0x(exp[:])))
		}
	}
	cmpAddr := func(name string, got, exp common.Address) {
		if got != exp {
			problems = append(problems, fmt.Sprintf("%s onchain %s != %s", name, got.Hex(), exp.Hex()))
		}
	}
	cmpAddr("customer", d.Customer, want.customer)
	cmp32("stackHash", d.StackHash, want.stackHash)
	cmp32("imageId", d.ImageId, want.imageID)
	cmp32("configHash", d.ConfigHash, want.configHash)
	cmpAddr("enclaveSigner", d.EnclaveSigner, want.enclaveSigner)
	switch {
	case want.quoteHash != nil && s.opts.Heartbeat:
		// DeploymentRegistry.heartbeat rejects a reused quote (QuoteReused) and a stale attestedAt (StaleHeartbeat).
		if d.QuoteHash == *want.quoteHash {
			problems = append(problems, "heartbeat reuses the recorded quote")
		}
		if want.attestedAt != nil && *want.attestedAt <= d.LastAttestedAt {
			problems = append(problems, fmt.Sprintf("heartbeat attestedAt %d is not after lastAttestedAt %d", *want.attestedAt, d.LastAttestedAt))
		}
	case want.quoteHash != nil:
		cmp32("quoteHash", d.QuoteHash, *want.quoteHash)
		// attestedAt is not covered by the quote, so the bundle's value only counts once the record vouches for it.
		if want.attestedAt != nil && *want.attestedAt != d.LastAttestedAt {
			problems = append(problems, fmt.Sprintf("attestedAt %d != recorded lastAttestedAt %d", *want.attestedAt, d.LastAttestedAt))
		}
	}
	if want.eventLogHash != nil {
		cmp32("eventLogHash", d.EventLogHash, *want.eventLogHash)
	}
	if want.eventLogHashInfo != nil {
		data["eventLogMatchesRecord"] = d.EventLogHash == *want.eventLogHashInfo
	}
	if len(problems) > 0 {
		s.rep.fail(CheckOnchainRecord, joinProblems(problems), data)
		return
	}
	s.rep.pass(CheckOnchainRecord, "DeploymentRegistry record matches", data)
}

func (s *session) checkExpectedCustomer() {
	if s.opts.ExpectedCustomer == nil {
		return
	}
	if s.cfg == nil {
		s.rep.fail(CheckExpectedCustomer, "no config", nil)
		return
	}
	if s.cfg.customer != *s.opts.ExpectedCustomer {
		s.rep.failf(CheckExpectedCustomer, "stack belongs to %s, expected %s", s.cfg.customer.Hex(), s.opts.ExpectedCustomer.Hex())
		return
	}
	s.rep.pass(CheckExpectedCustomer, "customer is "+s.cfg.customer.Hex(), nil)
}

// checkExpectedApps requires every Options.ExpectedAppIDs entry among config.apps[].id.
func (s *session) checkExpectedApps() {
	if len(s.opts.ExpectedAppIDs) == 0 {
		return
	}
	if s.cfg == nil {
		s.rep.fail(CheckExpectedApps, "no config", nil)
		return
	}
	have := make([]string, len(s.cfg.Apps))
	for i, a := range s.cfg.Apps {
		have[i] = a.ID
	}
	var missing []string
	for _, id := range s.opts.ExpectedAppIDs {
		if !slices.Contains(have, id) {
			missing = append(missing, id)
		}
	}
	data := map[string]any{"apps": have, "expected": s.opts.ExpectedAppIDs}
	if len(missing) > 0 {
		s.rep.fail(CheckExpectedApps, fmt.Sprintf("stack lacks %q", missing), data)
		return
	}
	s.rep.pass(CheckExpectedApps, "stack runs the expected apps", data)
}

func sameIDSet(a, b [][32]byte) bool {
	if len(a) != len(b) || hasDuplicates(a) || hasDuplicates(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func hasDuplicates(ids [][32]byte) bool {
	seen := map[[32]byte]bool{}
	for _, id := range ids {
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

func idList(ids [][32]byte) string {
	out := "["
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += hex0x(id[:])
	}
	return out + "]"
}

func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func joinProblems(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// canonicalHash is sha256(CJSON(raw)).
func canonicalHash(raw []byte) ([32]byte, error) {
	canon, err := cjson.Canonicalize(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canon), nil
}
