package verify

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// evidenceFields are the decoded byte fields of a bundle.
type evidenceFields struct {
	deploymentID  [32]byte
	customer      common.Address
	imageID       [32]byte
	releaseIDs    [][32]byte
	configHash    [32]byte
	stackHash     [32]byte
	enclaveSigner common.Address
	nonce2        [32]byte
	quote         []byte
	quoteHash     [32]byte
	eventLogHash  [32]byte
}

func decodeBundle(b *Bundle) (*evidenceFields, error) {
	if b.Schema != EvidenceSchema {
		return nil, fmt.Errorf("schema %q, want %q", b.Schema, EvidenceSchema)
	}
	if b.Runtime != RuntimeDstack {
		return nil, fmt.Errorf("runtime %q, want %q", b.Runtime, RuntimeDstack)
	}
	if b.AttestedAt == 0 {
		return nil, fmt.Errorf("attestedAt missing")
	}
	if b.AppCompose == "" || len(b.Config) == 0 || len(b.EventLog) == 0 {
		return nil, fmt.Errorf("appCompose, config and eventLog are required")
	}
	var f evidenceFields
	var err error
	fields32 := []struct {
		name string
		src  string
		dst  *[32]byte
	}{
		{"deploymentId", b.DeploymentID, &f.deploymentID},
		{"imageId", b.ImageID, &f.imageID},
		{"configHash", b.ConfigHash, &f.configHash},
		{"stackHash", b.StackHash, &f.stackHash},
		{"nonce2", b.Nonce2, &f.nonce2},
		{"quoteHash", b.QuoteHash, &f.quoteHash},
		{"eventLogHash", b.EventLogHash, &f.eventLogHash},
	}
	for _, x := range fields32 {
		if *x.dst, err = hexb.Decode32(x.src); err != nil {
			return nil, fmt.Errorf("%s: %w", x.name, err)
		}
	}
	if f.customer, err = parseAddress(b.Customer); err != nil {
		return nil, fmt.Errorf("customer: %w", err)
	}
	if f.enclaveSigner, err = parseAddress(b.EnclaveSigner); err != nil {
		return nil, fmt.Errorf("enclaveSigner: %w", err)
	}
	if f.releaseIDs, err = parseIDs(b.ReleaseIDs); err != nil {
		return nil, fmt.Errorf("releaseIds%w", err)
	}
	if f.quote, err = hexb.Decode(b.Quote, -1); err != nil || len(f.quote) == 0 {
		return nil, fmt.Errorf("quote: invalid or empty hex")
	}
	return &f, nil
}

// VerifyEvidenceJSON parses raw as an evidence bundle and verifies it. A bundle that does not parse yields a
// failed report, not an error.
func VerifyEvidenceJSON(ctx context.Context, raw []byte, deps Deps, opts Options) (*Report, error) {
	b, err := ParseBundle(raw)
	if err != nil {
		if verr := deps.validate(); verr != nil {
			return nil, verr
		}
		rep := newReport(ModeEvidence, deps.now())
		rep.fail(CheckBundle, err.Error(), nil)
		return rep.finish(), nil
	}
	return VerifyEvidence(ctx, b, deps, opts)
}

// VerifyEvidence runs every check of spec 8.4 and INTERFACES.md section 9 on an evidence bundle. The error is
// only for unusable dependencies; verification failures are reported in the Report.
func VerifyEvidence(ctx context.Context, b *Bundle, deps Deps, opts Options) (*Report, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	now := deps.now()
	rep := newReport(ModeEvidence, now)
	f, err := decodeBundle(b)
	if err != nil {
		rep.failf(CheckBundle, "malformed evidence bundle: %v", err)
		return rep.finish(), nil
	}
	rep.DeploymentID = hex0x(f.deploymentID[:])
	rep.StackHash = hex0x(f.stackHash[:])

	s := &session{ctx: ctx, deps: deps, chain: deps.Chain, opts: opts, rep: rep, cfgRaw: b.Config, appCompose: []byte(b.AppCompose)}
	s.stackHash = sha256.Sum256(s.appCompose)
	cfg, cfgErr := parseConfig(b.Config)
	if cfgErr != nil {
		rep.failf(CheckBundle, "config: %v", cfgErr)
	} else {
		s.cfg = cfg
		rep.pass(CheckBundle, fmt.Sprintf("%s, runtime %s, %d releases", EvidenceSchema, b.Runtime, len(f.releaseIDs)), nil)
	}

	s.checkChain(b.ChainID, &b.Contracts)

	if got := sha256.Sum256(f.quote); got != f.quoteHash {
		rep.failf(CheckQuoteHash, "sha256(quote) = %s, bundle says %s", hex0x(got[:]), hex0x(f.quoteHash[:]))
	} else {
		rep.pass(CheckQuoteHash, "quoteHash = sha256(quote)", nil)
	}
	s.checkQuote(f.quote)
	s.checkImage(f.imageID)

	if got, err := canonicalHash(b.EventLog); err != nil {
		rep.failf(CheckEventLogHash, "event log is not canonicalizable: %v", err)
	} else if got != f.eventLogHash {
		rep.failf(CheckEventLogHash, "sha256(CJSON(eventLog)) = %s, bundle says %s", hex0x(got[:]), hex0x(f.eventLogHash[:]))
	} else {
		rep.pass(CheckEventLogHash, "eventLogHash = sha256(CJSON(eventLog))", nil)
	}
	s.checkEventLog(b.EventLog)
	s.checkComposeHash(&f.stackHash)

	if s.computeConfigHash() {
		if s.configHash != f.configHash {
			rep.failf(CheckConfigHash, "sha256(CJSON(config)) = %s, bundle says %s", hex0x(s.configHash[:]), hex0x(f.configHash[:]))
		} else {
			rep.pass(CheckConfigHash, "configHash = sha256(CJSON(config))", nil)
		}
	}
	s.checkEvidenceConfigBinding(b, f)
	derived := s.checkDeploymentID(f.deploymentID)

	want := attest.EvidenceReportData(f.stackHash, f.configHash, f.enclaveSigner, f.nonce2, b.AttestedAt)
	s.checkReportData(want, "sha256(\"sealed/evidence/v1\" || stackHash || configHash || enclaveSigner || nonce2 || uint64be(attestedAt))")
	if opts.MaxEvidenceAge > 0 {
		s.checkEvidenceFreshness(b.AttestedAt, now)
	}

	s.checkReleases()
	s.checkRecompute(derived)
	s.checkApproval()
	s.checkExpectedCustomer()
	s.checkExpectedApps()
	attestedAt := b.AttestedAt
	s.checkRecord(recordExpectation{
		deploymentID: f.deploymentID, customer: f.customer, stackHash: f.stackHash, imageID: f.imageID,
		configHash: f.configHash, enclaveSigner: f.enclaveSigner, quoteHash: &f.quoteHash, attestedAt: &attestedAt,
		eventLogHash: &f.eventLogHash,
	})

	// The digest the oracle signs for registerDeployment (informational).
	ctx2, cancel := s.callCtx()
	defer cancel()
	if d, err := s.chain.RecordDigest(ctx2, chain.Record{
		DeploymentId: f.deploymentID, Customer: f.customer, StackHash: f.stackHash, ImageId: f.imageID,
		QuoteHash: f.quoteHash, EventLogHash: f.eventLogHash, ConfigHash: f.configHash, EnclaveSigner: f.enclaveSigner,
		AttestedAt: b.AttestedAt,
	}); err == nil {
		rep.RecordDigest = hex0x(d[:])
	}
	return rep.finish(), nil
}

// checkEvidenceConfigBinding requires the bundle's customer, image, chain and release list to be the config's.
func (s *session) checkEvidenceConfigBinding(b *Bundle, f *evidenceFields) {
	if s.cfg == nil {
		s.rep.fail(CheckConfigBinding, "no config", nil)
		return
	}
	var problems []string
	if s.cfg.customer != f.customer {
		problems = append(problems, fmt.Sprintf("config.customer %s != bundle customer %s", s.cfg.customer.Hex(), f.customer.Hex()))
	}
	if s.cfg.imageID != f.imageID {
		problems = append(problems, fmt.Sprintf("config.imageId %s != bundle imageId %s", hex0x(s.cfg.imageID[:]), hex0x(f.imageID[:])))
	}
	if s.cfg.ChainID != b.ChainID {
		problems = append(problems, fmt.Sprintf("config.chainId %d != bundle chainId %d", s.cfg.ChainID, b.ChainID))
	}
	if !sameIDSet(s.cfg.releaseIDs, f.releaseIDs) {
		problems = append(problems, fmt.Sprintf("bundle releaseIds %s != config releases %s", idList(f.releaseIDs), idList(s.cfg.releaseIDs)))
	}
	if !slices.IsSortedFunc(s.cfg.Apps, func(a, b ConfigApp) int { return compareStrings(a.ID, b.ID) }) {
		problems = append(problems, "config.apps is not sorted by id")
	}
	if len(problems) > 0 {
		s.rep.fail(CheckConfigBinding, joinProblems(problems), nil)
		return
	}
	s.rep.pass(CheckConfigBinding, "customer, image, chain and releases agree with the config", nil)
}

// checkDeploymentID derives keccak256(abi.encode(customer, stackHash, salt)) and compares it with claimed (and
// with Options.ExpectedDeploymentID). It returns the derived id.
func (s *session) checkDeploymentID(claimed [32]byte) [32]byte {
	if s.cfg == nil {
		s.rep.fail(CheckDeploymentID, "no config", nil)
		return [32]byte{}
	}
	derived := DeploymentID(s.cfg.customer, s.stackHash, s.cfg.salt)
	data := map[string]any{"derived": hex0x(derived[:])}
	var problems []string
	if derived != claimed {
		problems = append(problems, fmt.Sprintf("keccak256(abi.encode(customer, stackHash, salt)) = %s, bundle says %s", hex0x(derived[:]), hex0x(claimed[:])))
	}
	if s.opts.ExpectedDeploymentID != nil && *s.opts.ExpectedDeploymentID != derived {
		problems = append(problems, fmt.Sprintf("expected deployment %s", hex0x(s.opts.ExpectedDeploymentID[:])))
	}
	if len(problems) > 0 {
		s.rep.fail(CheckDeploymentID, joinProblems(problems), data)
		return derived
	}
	s.rep.pass(CheckDeploymentID, "deploymentId = keccak256(abi.encode(customer, stackHash, salt))", data)
	return derived
}

func (s *session) checkReportData(want attest.ReportData, construction string) {
	if s.quote == nil {
		s.rep.fail(CheckReportData, "no parsable quote", nil)
		return
	}
	data := map[string]any{"expected": hex0x(want[:]), "quote": hex0x(s.quote.ReportData[:])}
	if s.quote.ReportData != want {
		s.rep.fail(CheckReportData, "quote report_data does not equal "+construction, data)
		return
	}
	s.rep.pass(CheckReportData, "report_data = "+construction, data)
}

func (s *session) checkEvidenceFreshness(attestedAt uint64, now time.Time) {
	at := time.Unix(int64(attestedAt), 0)
	data := map[string]any{"attestedAt": attestedAt, "maxAgeSeconds": int64(s.opts.MaxEvidenceAge / time.Second)}
	switch {
	case at.After(now.Add(maxFutureSkew)):
		s.rep.fail(CheckFreshness, fmt.Sprintf("attestedAt %s is in the future", at.UTC().Format(time.RFC3339)), data)
	case now.Sub(at) > s.opts.MaxEvidenceAge:
		s.rep.fail(CheckFreshness, fmt.Sprintf("evidence is %s old, limit %s", now.Sub(at).Round(time.Second), s.opts.MaxEvidenceAge), data)
	default:
		// attestedAt is inside report_data (D-047), so this age is the quote's own once report_data passes, also
		// before the deployment is registered (the oracle's first verification).
		s.rep.pass(CheckFreshness, fmt.Sprintf("attested %s ago (attestedAt is bound in report_data)", now.Sub(at).Round(time.Second)), data)
	}
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
