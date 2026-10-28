package keybroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/runtime/composer/cjson"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// Additional check and reason names.
const (
	// CheckConfigChain requires config.chainId and config.contracts to name this broker's chain and registries.
	CheckConfigChain = "config_chain"
	// CheckChain pins every registry read of the decision to the current head block.
	CheckChain = "chain"
	// ReasonInternal answers 500: a defect in the broker itself.
	ReasonInternal = "internal"
)

// Outcome is the answer to one release request.
type Outcome struct {
	Status   int
	Body     any // *ReleaseResponse or *Denial
	Decision *Decision
}

// stop ends the pipeline.
type stop struct {
	status   int
	decision string
	reason   string
	detail   string
}

type session struct {
	b   *Broker
	d   *Decision
	req *releaseRequest

	quote      *attest.Quote
	reg        Registry
	runtime    *attest.RuntimeInfo
	stackHash  [32]byte
	cfg        *composer.Config
	customer   common.Address
	releaseIDs [][32]byte
	bundles    map[string]*composer.Bundle
	deployment [32]byte
}

// Release runs the whole pipeline for one POST /v1/release body. remote is recorded in the decision log only.
func (b *Broker) Release(ctx context.Context, body []byte, remote string) *Outcome {
	start := b.deps.Now()
	s := &session{b: b, d: &Decision{Time: start.UTC(), RequestID: newRequestID(), Remote: remote, Checks: []Check{}}}
	rctx, cancel := context.WithTimeout(ctx, b.cfg.ReleaseTimeout)
	resp, st := s.run(rctx, body)
	cancel()

	out := &Outcome{Decision: s.d}
	if st != nil {
		s.d.Decision, s.d.Reason, s.d.Detail, s.d.HTTPStatus = st.decision, st.reason, st.detail, st.status
		s.d.Released = nil
		out.Status, out.Body = st.status, &Denial{Decision: st.decision, Reason: st.reason, Detail: st.detail}
	} else {
		s.d.Decision, s.d.HTTPStatus = DecisionAllowed, http.StatusOK
		out.Status, out.Body = http.StatusOK, resp
	}
	s.d.DurationMS = b.deps.Now().Sub(start).Milliseconds()

	// The log write must happen even when the caller went away or the release deadline passed.
	lctx, lcancel := context.WithTimeout(context.WithoutCancel(ctx), b.cfg.LogTimeout)
	err := b.deps.Log.Write(lctx, s.d)
	lcancel()
	if err != nil {
		b.deps.OpLog.Error("decision log write failed", "err", err, "requestId", s.d.RequestID, "decision", s.d.Decision,
			"reason", s.d.Reason, "stackHash", s.d.Hashes.StackHash)
		if out.Status == http.StatusOK {
			// No secrets leave without an audit record.
			detail := "the decision could not be written to the customer's log; nothing was released"
			s.d.Decision, s.d.Reason, s.d.Detail, s.d.HTTPStatus, s.d.Released = DecisionError, ReasonLogFailed, detail, http.StatusServiceUnavailable, nil
			out.Status, out.Body = http.StatusServiceUnavailable, &Denial{Decision: DecisionError, Reason: ReasonLogFailed, Detail: detail}
		}
	}
	b.deps.OpLog.Info("release decision", "requestId", s.d.RequestID, "decision", s.d.Decision, "reason", s.d.Reason,
		"stackHash", s.d.Hashes.StackHash, "simulated", s.d.Simulated, "durationMs", s.d.DurationMS)
	return out
}

func (s *session) pass(name, detail string, data map[string]any) {
	s.d.Checks = append(s.d.Checks, Check{Name: name, OK: true, Detail: detail, Data: data})
}

// maxDetail bounds a detail string; details can quote request content and land in every log entry.
const maxDetail = 2000

func clip(detail string) string {
	if len(detail) <= maxDetail {
		return detail
	}
	return detail[:maxDetail] + "..."
}

func (s *session) deny(name, reason, detail string, data map[string]any) *stop {
	detail = clip(detail)
	s.d.Checks = append(s.d.Checks, Check{Name: name, OK: false, Reason: reason, Detail: detail, Data: data})
	return &stop{status: http.StatusForbidden, decision: DecisionDenied, reason: reason, detail: detail}
}

func (s *session) badRequest(name, detail string) *stop {
	detail = clip(detail)
	s.d.Checks = append(s.d.Checks, Check{Name: name, OK: false, Reason: ReasonBadRequest, Detail: detail})
	return &stop{status: http.StatusBadRequest, decision: DecisionDenied, reason: ReasonBadRequest, detail: detail}
}

// unavailable is a dependency failure (RPC, catalog, Secret Manager, KMS): 503, retried by the agent.
func (s *session) unavailable(name, reason, detail string) *stop {
	if reason == "" {
		reason = ReasonUnavailable
	}
	detail = clip(detail)
	s.d.Checks = append(s.d.Checks, Check{Name: name, OK: false, Reason: reason, Detail: detail})
	return &stop{status: http.StatusServiceUnavailable, decision: DecisionError, reason: reason, detail: detail}
}

func (s *session) internal(name, detail string) *stop {
	s.d.Checks = append(s.d.Checks, Check{Name: name, OK: false, Reason: ReasonInternal, Detail: detail})
	return &stop{status: http.StatusInternalServerError, decision: DecisionError, reason: ReasonInternal, detail: detail}
}

func (s *session) run(ctx context.Context, body []byte) (*ReleaseResponse, *stop) {
	m, err := parseEnvelope(body)
	if err != nil {
		return nil, s.badRequest(CheckRequest, err.Error())
	}
	// The nonce is consumed before anything else is looked at, so every attempt burns it.
	nonce, err := requestNonce(m)
	if err != nil {
		return nil, s.deny(CheckNonce, ReasonBadNonce, err.Error(), nil)
	}
	s.d.Hashes.Nonce = hex0x(nonce[:])
	if err := s.b.deps.Nonces.Consume(nonce); err != nil {
		return nil, s.deny(CheckNonce, ReasonBadNonce, err.Error(), nil)
	}
	s.pass(CheckNonce, "issued by this broker, unused and unexpired; now consumed", nil)

	req, err := parseRequest(m)
	if err != nil {
		return nil, s.badRequest(CheckRequest, err.Error())
	}
	s.req = req
	h := &s.d.Hashes
	h.EphemeralPub = hex0x(req.EphemeralPub[:])
	if len(req.Quote) > 0 {
		qh := sha256.Sum256(req.Quote)
		h.QuoteHash = hex0x(qh[:])
	}
	elh := sha256.Sum256(req.EventLog)
	h.EventLogHash = hex0x(elh[:])
	h.ImageID = hex0x(req.ImageID[:])
	for _, id := range req.ReleaseIDs {
		h.ReleaseIDs = append(h.ReleaseIDs, hex0x(id[:]))
	}
	s.pass(CheckRequest, "well-formed", map[string]any{"quoteBytes": len(req.Quote), "appComposeBytes": len(req.AppCompose), "configBytes": len(req.Config)})

	for _, step := range []func(context.Context) *stop{
		s.checkQuote, s.checkReportData, s.pinChain, s.checkImage, s.checkRTMR3, s.checkComposeHash,
		s.checkRecompute, s.checkCustomer, s.checkConfigChain, s.checkApproval,
	} {
		if st := step(ctx); st != nil {
			return nil, st
		}
	}
	return s.release(ctx)
}

func (s *session) checkQuote(ctx context.Context) *stop {
	if len(s.req.Quote) == 0 {
		return s.deny(CheckQuote, ReasonQuoteInvalid, "no TDX quote: secrets are released only to Intel TDX confidential VMs", nil)
	}
	res, err := s.b.deps.Quotes.VerifyQuote(ctx, s.req.Quote)
	if err != nil {
		if ctx.Err() != nil {
			return s.unavailable(CheckQuote, "", "quote verification did not finish: "+ctx.Err().Error())
		}
		reason := ReasonQuoteInvalid
		if errors.Is(err, attest.ErrTCBStatus) {
			reason = ReasonTCBStatus
		}
		return s.deny(CheckQuote, reason, err.Error(), nil)
	}
	if res.Simulated && !s.b.cfg.AllowSimulated {
		return s.deny(CheckQuote, ReasonQuoteInvalid, "simulated quote refused: this key broker only accepts hardware TDX quotes", nil)
	}
	s.quote = res.Quote
	s.d.Simulated = res.Simulated
	data := map[string]any{"simulated": res.Simulated, "tcbStatus": res.TCBStatus, "qeTcbStatus": res.QETCBStatus}
	if !res.Simulated {
		data["quoteVersion"] = res.Quote.Version
		data["platformTcbStatus"] = res.PlatformTCBStatus
		data["moduleTcbStatus"] = res.ModuleTCBStatus
		data["fmspc"] = res.FMSPC
		data["tcbDate"] = res.TCBDate
		data["advisoryIds"] = res.AdvisoryIDs
	}
	detail := fmt.Sprintf("TDX quote verified with Intel collateral, TCB %s", res.TCBStatus)
	if res.Simulated {
		detail = "DEV: simulated quote accepted by a dev build with SEALED_DEV_SIM=1; no hardware attestation"
	}
	s.pass(CheckQuote, detail, data)
	return nil
}

func (s *session) checkReportData(context.Context) *stop {
	want := attest.KeyReleaseReportData(s.req.Nonce, s.req.EphemeralPub)
	data := map[string]any{"quote": hex0x(s.quote.ReportData[:]), "expected": hex0x(want[:])}
	if s.quote.ReportData != want {
		return s.deny(CheckReportData, ReasonReportDataMismatch,
			`report_data is not sha256("sealed/kb-release/v1" || nonce || ephemeralPub) || 32 zero bytes`, data)
	}
	s.pass(CheckReportData, "binds this nonce and ephemeral key", data)
	return nil
}

func (s *session) pinChain(ctx context.Context) *stop {
	if err := s.b.CheckChain(ctx); err != nil {
		return s.unavailable(CheckChain, "", err.Error())
	}
	reg, block, err := s.b.deps.Chain.Pin(ctx)
	if err != nil {
		return s.unavailable(CheckChain, "", err.Error())
	}
	s.reg = reg
	s.d.Hashes.BlockNumber = block
	s.pass(CheckChain, fmt.Sprintf("registry reads pinned to block %d of chain %d", block, s.b.cfg.ChainID), map[string]any{"blockNumber": block})
	return nil
}

func (s *session) checkImage(ctx context.Context) *stop {
	id := s.req.ImageID
	img, err := s.reg.GetImage(ctx, id)
	if errors.Is(err, chain.ErrNotFound) {
		return s.deny(CheckImage, ReasonImageNotApproved, fmt.Sprintf("image %s is not registered in PlatformRegistry", hex0x(id[:])), nil)
	}
	if err != nil {
		return s.unavailable(CheckImage, "", "PlatformRegistry.getImage: "+err.Error())
	}
	mh := s.quote.MeasurementsHash()
	s.d.Hashes.MeasurementsHash = hex0x(mh[:])
	data := map[string]any{"imageId": hex0x(id[:]), "name": img.Name, "version": img.Version, "onchain": hex0x(img.MeasurementsHash[:]),
		"quote": hex0x(mh[:]), "isDebug": img.IsDebug, "status": img.Status, "tdAttributes": hex0x(s.quote.TDAttributes[:])}
	if mh != img.MeasurementsHash {
		return s.deny(CheckImage, ReasonMeasurementsMismatch, fmt.Sprintf("keccak256(mrtd || rtmr0 || rtmr1 || rtmr2) of the quote is %s, image %s %s has %s",
			hex0x(mh[:]), img.Name, img.Version, hex0x(img.MeasurementsHash[:])), data)
	}
	if img.IsDebug {
		return s.deny(CheckImage, ReasonImageDebug, fmt.Sprintf("image %s %s is a debug image; debug images never get production secrets", img.Name, img.Version), data)
	}
	if err := s.quote.CheckProductionAttributes(); err != nil {
		return s.deny(CheckImage, ReasonImageDebug, err.Error(), data)
	}
	approved, err := s.reg.IsApprovedImage(ctx, id)
	if err != nil {
		return s.unavailable(CheckImage, "", "PlatformRegistry.isApprovedImage: "+err.Error())
	}
	if !approved {
		return s.deny(CheckImage, ReasonImageNotApproved, fmt.Sprintf("image %s %s is not approved (status %d)", img.Name, img.Version, img.Status), data)
	}
	s.pass(CheckImage, fmt.Sprintf("measurements match approved production image %s %s", img.Name, img.Version), data)
	return nil
}

func (s *session) checkRTMR3(context.Context) *stop {
	evs, err := attest.ParseEventLog(s.req.EventLog)
	if err != nil {
		return s.deny(CheckRTMR3, ReasonRTMR3Replay, err.Error(), nil)
	}
	info, err := attest.CheckRuntimeEvents(evs, s.quote.RTMR[3])
	if err != nil {
		return s.deny(CheckRTMR3, ReasonRTMR3Replay, err.Error(), map[string]any{"quoteRtmr3": hex0x(s.quote.RTMR[3][:])})
	}
	s.runtime = info
	s.d.Hashes.RTMR3 = hex0x(info.RTMR3[:])
	s.d.Hashes.ComposeHash = hex0x(info.ComposeHash[:])
	s.pass(CheckRTMR3, "event log replays to the quote's RTMR3 with the exact Sealed event sequence", map[string]any{
		"rtmr3": hex0x(info.RTMR3[:]), "composeHash": hex0x(info.ComposeHash[:]), "keyProvider": info.KeyProvider,
		"storageFs": info.StorageFS, "storageEncrypted": info.StorageEncrypted,
	})
	return nil
}

func (s *session) checkComposeHash(context.Context) *stop {
	s.stackHash = sha256.Sum256(s.req.AppCompose)
	s.d.Hashes.StackHash = hex0x(s.stackHash[:])
	if s.runtime.ComposeHash != s.stackHash {
		return s.deny(CheckComposeHash, ReasonComposeMismatch, fmt.Sprintf("the booted compose-hash %s is not sha256(appCompose) %s",
			hex0x(s.runtime.ComposeHash[:]), hex0x(s.stackHash[:])), nil)
	}
	s.pass(CheckComposeHash, "compose-hash event = sha256(appCompose) = stackHash", nil)
	return nil
}

func (s *session) checkRecompute(ctx context.Context) *stop {
	cfg, err := composer.ParseConfig(s.req.Config)
	if err != nil {
		return s.deny(CheckStackRecompute, ReasonComposeMismatch, err.Error(), nil)
	}
	s.cfg = cfg
	s.customer = common.HexToAddress(cfg.Customer)
	s.d.Hashes.Customer = strings.ToLower(s.customer.Hex())
	if ch, err := cfg.Hash(); err == nil {
		s.d.Hashes.ConfigHash = ch.Hex()
	}
	for _, a := range cfg.Apps {
		id, err := composer.ParseHash(a.ReleaseID)
		if err != nil {
			return s.deny(CheckStackRecompute, ReasonComposeMismatch, fmt.Sprintf("config app %s: %v", a.ID, err), nil)
		}
		s.releaseIDs = append(s.releaseIDs, [32]byte(id))
	}
	if !slices.Equal(s.releaseIDs, s.req.ReleaseIDs) {
		return s.deny(CheckStackRecompute, ReasonComposeMismatch, fmt.Sprintf("releaseIds %s differ from config.apps[].releaseId %s",
			idList(s.req.ReleaseIDs), idList(s.releaseIDs)), nil)
	}
	refs := make([]BundleRef, len(cfg.Apps))
	var releases []map[string]any
	for i, a := range cfg.Apps {
		id := s.releaseIDs[i]
		rel, err := s.reg.GetRelease(ctx, id)
		if errors.Is(err, chain.ErrNotFound) {
			return s.deny(CheckStackRecompute, ReasonComposeMismatch, fmt.Sprintf("%s release %s is not published in AppRegistry", a.ID, hex0x(id[:])), nil)
		}
		if err != nil {
			return s.unavailable(CheckStackRecompute, "", "AppRegistry.getRelease: "+err.Error())
		}
		if want := crypto.Keccak256Hash([]byte(a.ID)); rel.AppId != want {
			return s.deny(CheckStackRecompute, ReasonComposeMismatch, fmt.Sprintf("release %s belongs to app %s, not %q", hex0x(id[:]), hex0x(rel.AppId[:]), a.ID), nil)
		}
		refs[i] = BundleRef{App: a.ID, Version: rel.Version, BundleHash: rel.BundleHash}
		releases = append(releases, map[string]any{"app": a.ID, "releaseId": hex0x(id[:]), "version": rel.Version, "bundleHash": hex0x(rel.BundleHash[:])})
	}

	bundles := make([]*composer.Bundle, len(refs))
	errs := make([]error, len(refs))
	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Go(func() { bundles[i], errs[i] = s.b.deps.Bundles.Fetch(ctx, ref) })
	}
	wg.Wait()
	data := map[string]any{"composerVersion": composer.Version, "releases": releases}
	for i, err := range errs {
		if err == nil {
			continue
		}
		what := fmt.Sprintf("%s %s bundle: %v", refs[i].App, refs[i].Version, err)
		switch {
		case errors.Is(err, ErrBundleHashMismatch):
			return s.deny(CheckStackRecompute, ReasonBundleHashMismatch, what, data)
		case errors.Is(err, ErrBundleInvalid):
			return s.deny(CheckStackRecompute, ReasonComposeMismatch, what, data)
		default:
			return s.unavailable(CheckStackRecompute, "", what)
		}
	}
	s.bundles = map[string]*composer.Bundle{}
	for i, b := range bundles {
		s.bundles[refs[i].App] = b
	}
	res, err := composer.Compose(cfg, bundles)
	if err != nil {
		return s.deny(CheckStackRecompute, ReasonComposeMismatch, "composer: "+err.Error(), data)
	}
	data["recomputedStackHash"] = res.StackHash.Hex()
	if !bytes.Equal(res.AppCompose, s.req.AppCompose) || [32]byte(res.StackHash) != s.stackHash {
		return s.deny(CheckStackRecompute, ReasonComposeMismatch, fmt.Sprintf("composer %s recomputes a different app-compose.json (%d vs %d bytes, first difference at byte %d)",
			composer.Version, len(res.AppCompose), len(s.req.AppCompose), firstDiff(res.AppCompose, s.req.AppCompose)), data)
	}
	s.deployment = res.DeploymentID
	s.d.Hashes.ConfigHash = res.ConfigHash.Hex()
	s.d.Hashes.DeploymentID = res.DeploymentID.Hex()
	s.pass(CheckStackRecompute, fmt.Sprintf("app-compose.json recomputed byte for byte by composer %s from the config and %d onchain releases", composer.Version, len(refs)), data)
	return nil
}

func (s *session) checkCustomer(context.Context) *stop {
	data := map[string]any{"config": strings.ToLower(s.customer.Hex()), "broker": strings.ToLower(s.b.cfg.Customer.Hex())}
	if s.customer != s.b.cfg.Customer {
		return s.deny(CheckCustomer, ReasonCustomerMismatch, fmt.Sprintf("config.customer %s is not this key broker's customer %s",
			strings.ToLower(s.customer.Hex()), strings.ToLower(s.b.cfg.Customer.Hex())), data)
	}
	s.pass(CheckCustomer, "config.customer is the bootstrap customer", data)
	return nil
}

func (s *session) checkConfigChain(context.Context) *stop {
	want := s.b.cfg.Contracts
	var problems []string
	if uint64(s.cfg.ChainID) != s.b.cfg.ChainID {
		problems = append(problems, fmt.Sprintf("config.chainId %d, this key broker reads chain %d", s.cfg.ChainID, s.b.cfg.ChainID))
	}
	for _, c := range []struct {
		name string
		got  string
		want common.Address
	}{
		{"platformRegistry", s.cfg.Contracts.PlatformRegistry, want.PlatformRegistry},
		{"appRegistry", s.cfg.Contracts.AppRegistry, want.AppRegistry},
		{"deploymentRegistry", s.cfg.Contracts.DeploymentRegistry, want.DeploymentRegistry},
	} {
		if common.HexToAddress(c.got) != c.want {
			problems = append(problems, fmt.Sprintf("config.contracts.%s %s, this key broker reads %s", c.name, c.got, strings.ToLower(c.want.Hex())))
		}
	}
	if len(problems) > 0 {
		return s.deny(CheckConfigChain, ReasonStackNotApproved, strings.Join(problems, "; "), nil)
	}
	s.pass(CheckConfigChain, "config names this key broker's chain and registries", nil)
	return nil
}

func (s *session) checkApproval(ctx context.Context) *stop {
	data := map[string]any{"customer": strings.ToLower(s.customer.Hex()), "stackHash": hex0x(s.stackHash[:])}
	ok, err := s.reg.IsStackApproved(ctx, s.customer, s.stackHash)
	if err != nil {
		return s.unavailable(CheckStackApproved, "", "DeploymentRegistry.isStackApproved: "+err.Error())
	}
	if !ok {
		return s.deny(CheckStackApproved, ReasonStackNotApproved, "the customer's approval of this stack is missing, revoked or expired, or one of its releases or its image is no longer active", data)
	}
	s.pass(CheckStackApproved, "DeploymentRegistry.isStackApproved(customer, stackHash)", data)

	ap, err := s.reg.GetStackApproval(ctx, s.customer, s.stackHash)
	if err != nil {
		return s.unavailable(CheckApprovalReleases, "", "DeploymentRegistry.getStackApproval: "+err.Error())
	}
	cfgImage, _ := composer.ParseHash(s.cfg.ImageID)
	data = map[string]any{"approvedReleaseIds": idList(ap.ReleaseIDs), "approvedImageId": hex0x(ap.ImageID[:]), "approvedAt": ap.ApprovedAt, "expiry": ap.Expiry}
	var problems []string
	if ap.ApprovedAt == 0 {
		problems = append(problems, "no approval stored for (customer, stackHash)")
	}
	if !sameIDSet(ap.ReleaseIDs, s.releaseIDs) {
		problems = append(problems, fmt.Sprintf("approved releases %s are not the config's releases %s", idList(ap.ReleaseIDs), idList(s.releaseIDs)))
	}
	if ap.ImageID != [32]byte(cfgImage) {
		problems = append(problems, fmt.Sprintf("approved image %s is not config.imageId %s", hex0x(ap.ImageID[:]), cfgImage.Hex()))
	}
	if s.req.ImageID != [32]byte(cfgImage) {
		problems = append(problems, fmt.Sprintf("request imageId %s is not config.imageId %s", hex0x(s.req.ImageID[:]), cfgImage.Hex()))
	}
	if len(problems) > 0 {
		return s.deny(CheckApprovalReleases, ReasonStackNotApproved, strings.Join(problems, "; "), data)
	}
	s.pass(CheckApprovalReleases, "the approval names exactly the config's releases and image", data)
	return nil
}

// release reads the stack's secrets, derives the keys and seals everything to the ephemeral key.
func (s *session) release(ctx context.Context) (*ReleaseResponse, *stop) {
	apps := make([]string, len(s.cfg.Apps))
	for i, a := range s.cfg.Apps {
		apps[i] = a.ID
	}
	refs, err := PlanSecrets(apps, s.bundles)
	if err != nil {
		return nil, s.deny(CheckSecrets, ReasonComposeMismatch, "manifest secrets: "+err.Error(), nil)
	}
	vals, released, err := readSecrets(ctx, s.b.deps.Secrets, refs)
	if err != nil {
		var se *SecretError
		if errors.As(err, &se) {
			return nil, s.unavailable(CheckSecrets, se.Reason, se.Error())
		}
		return nil, s.unavailable(CheckSecrets, "", "Secret Manager: "+err.Error())
	}
	s.pass(CheckSecrets, fmt.Sprintf("%d secrets named by the stack's manifests", len(released)), map[string]any{"released": released})

	keys, err := DeriveKeys(ctx, s.b.deps.MAC, s.deployment)
	if err != nil {
		return nil, s.unavailable(CheckKeys, "", "KMS: "+err.Error())
	}
	s.pass(CheckKeys, "diskKey and signerSeed derived with the KMS HMAC key from the deploymentId", map[string]any{"deploymentId": hex0x(s.deployment[:])})

	for _, a := range apps {
		if vals[a] == nil {
			vals[a] = map[string]string{}
		}
	}
	pt := ReleasePlaintext{Secrets: vals, DiskKey: hex0x(keys.DiskKey[:]), SignerSeed: hex0x(keys.SignerSeed[:])}
	plain, err := cjson.Marshal(pt)
	clear(keys.DiskKey[:])
	clear(keys.SignerSeed[:])
	if err != nil {
		return nil, s.internal(CheckSeal, "encode release plaintext: "+err.Error())
	}
	enc, ct, err := SealRelease(s.req.EphemeralPub, s.req.Nonce, plain)
	clear(plain)
	if errors.Is(err, ErrBadEphemeralKey) {
		return nil, s.badRequest(CheckSeal, err.Error())
	}
	if err != nil {
		return nil, s.internal(CheckSeal, err.Error())
	}
	s.pass(CheckSeal, "HPKE X25519/HKDF-SHA256/AES-256-GCM to ephemeralPub, info sealed/kb-release/v1, aad nonce", nil)
	s.d.Released = append(released, "diskKey", "signerSeed")
	return &ReleaseResponse{
		StackHash:    hex0x(s.stackHash[:]),
		DeploymentID: hex0x(s.deployment[:]),
		Enc:          hex0x(enc),
		Ciphertext:   hex0x(ct),
	}, nil
}

func idList(ids [][32]byte) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = hex0x(id[:])
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func sameIDSet(a, b [][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[[32]byte]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
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
