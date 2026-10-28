package verify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// LiveOptions extend Options for a live attestation.
type LiveOptions struct {
	Options
	// Timeout bounds the whole /attest round trip; 0 means 30 seconds. The nonce is only accepted within it.
	Timeout time.Duration
	// RootCAs verifies the served certificate; nil means the system roots.
	RootCAs *x509.CertPool
	// InsecureSkipTLSVerify skips WebPKI validation of the served certificate (dev only: self-signed sslip
	// certificates). The quote still has to bind the key of the certificate actually served.
	InsecureSkipTLSVerify bool
}

const maxAttestBody = 8 << 20

// liveResponse is GET /attest (INTERFACES.md section 11).
type liveResponse struct {
	Quote         string          `json:"quote"`
	EventLog      json.RawMessage `json:"eventLog"`
	Config        json.RawMessage `json:"config"`
	ReleaseIDs    []string        `json:"releaseIds"`
	AppCompose    string          `json:"appCompose"`
	EnclaveSigner string          `json:"enclaveSigner"`
	TLSPubKeyHash string          `json:"tlsPubKeyHash"`
	ReportData    string          `json:"reportData"`
}

// fetched is one /attest exchange.
type fetched struct {
	nonce      [32]byte
	servedSPKI [32]byte
	elapsed    time.Duration
	resp       liveResponse
}

// VerifyLive fetches attestURL with a fresh random nonce over TLS and verifies the response: the live-attest
// report_data construction, freshness, that tlsPubKeyHash is the SPKI hash of the certificate served on that very
// connection, and then every stack check of an evidence verification against the current chain state.
func VerifyLive(ctx context.Context, attestURL string, deps Deps, opts LiveOptions) (*Report, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	rep := newReport(ModeLive, deps.now())
	f, err := fetchAttest(ctx, attestURL, opts)
	if err != nil {
		rep.fail(CheckLiveFetch, err.Error(), map[string]any{"url": attestURL})
		return rep.finish(), nil
	}
	rep.pass(CheckLiveFetch, fmt.Sprintf("GET /attest over TLS in %s", f.elapsed.Round(time.Millisecond)), map[string]any{
		"url": attestURL, "nonce": hex0x(f.nonce[:]), "elapsedMs": f.elapsed.Milliseconds(),
	})
	return verifyLiveResponse(ctx, f, deps, opts.Options, rep), nil
}

func fetchAttest(ctx context.Context, attestURL string, opts LiveOptions) (*fetched, error) {
	u, err := url.Parse(attestURL)
	if err != nil {
		return nil, fmt.Errorf("attest URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("attest URL must be https (the TLS key binding needs a TLS connection)")
	}
	f := &fetched{}
	if _, err := rand.Read(f.nonce[:]); err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("nonce", hex0x(f.nonce[:]))
	u.RawQuery = q.Encode()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs, InsecureSkipVerify: opts.InsecureSkipTLSVerify}, // #nosec G402 -- dev flag; the key binding is checked below
			DisableKeepAlives: true,
			Proxy:             http.ProxyFromEnvironment,
		},
		// A redirect would move the request to another connection; refuse it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u.Redacted(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestBody+1))
	f.elapsed = time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("read /attest: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/attest returned HTTP %d", resp.StatusCode)
	}
	if len(body) > maxAttestBody {
		return nil, errors.New("/attest response too large")
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no TLS peer certificate on the /attest connection")
	}
	f.servedSPKI = sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if err := json.Unmarshal(body, &f.resp); err != nil {
		return nil, fmt.Errorf("decode /attest: %w", err)
	}
	// dstack-style APIs return the event log as a JSON string; accept both shapes.
	var inner string
	if json.Unmarshal(f.resp.EventLog, &inner) == nil {
		f.resp.EventLog = json.RawMessage(inner)
	}
	return f, nil
}

func verifyLiveResponse(ctx context.Context, f *fetched, deps Deps, opts Options, rep *Report) *Report {
	r := f.resp
	quote, qErr := hexb.Decode(r.Quote, -1)
	tlsHash, tErr := hexb.Decode32(r.TLSPubKeyHash)
	signer, sErr := parseAddress(r.EnclaveSigner)
	claimedRD, rErr := hexb.Decode(r.ReportData, attest.ReportDataSize)
	releaseIDs, idErr := parseIDs(r.ReleaseIDs)
	if err := errors.Join(qErr, tErr, sErr, rErr, idErr); err != nil || len(quote) == 0 || r.AppCompose == "" {
		rep.failf(CheckBundle, "malformed /attest response: quote, tlsPubKeyHash, enclaveSigner, reportData, releaseIds and appCompose are required (%v)", err)
		return rep.finish()
	}

	s := &session{ctx: ctx, deps: deps, opts: opts, rep: rep, cfgRaw: r.Config, appCompose: []byte(r.AppCompose)}
	s.stackHash = sha256.Sum256(s.appCompose)
	rep.StackHash = hex0x(s.stackHash[:])
	cfg, err := parseConfig(r.Config)
	if err != nil {
		rep.failf(CheckBundle, "config: %v", err)
	} else {
		s.cfg = cfg
		rep.pass(CheckBundle, fmt.Sprintf("/attest response with %d releases", len(releaseIDs)), nil)
	}

	if tlsHash != f.servedSPKI {
		rep.fail(CheckTLSBinding, "tlsPubKeyHash is not the SPKI hash of the certificate served on this connection", map[string]any{
			"claimed": hex0x(tlsHash[:]), "served": hex0x(f.servedSPKI[:]),
		})
	} else {
		rep.pass(CheckTLSBinding, "tlsPubKeyHash = sha256(SPKI of the served certificate)", map[string]any{"tlsPubKeyHash": hex0x(tlsHash[:])})
	}

	s.checkChain(0, nil)
	s.checkQuote(quote)

	want := attest.LiveAttestReportData(f.nonce, f.servedSPKI, signer)
	if [attest.ReportDataSize]byte(claimedRD) != want {
		rep.fail(CheckFreshness, "reportData does not bind our nonce, the served TLS key and the enclave signer", map[string]any{"nonce": hex0x(f.nonce[:])})
	} else {
		rep.pass(CheckFreshness, fmt.Sprintf("fresh: our nonce is bound, answered in %s", f.elapsed.Round(time.Millisecond)), map[string]any{"nonce": hex0x(f.nonce[:])})
	}
	s.checkReportData(want, "sha256(\"sealed/attest/v1\" || nonce || sha256(served SPKI) || enclaveSigner)")

	var imageID [32]byte
	if s.cfg != nil {
		imageID = s.cfg.imageID
	}
	s.checkImage(imageID)
	s.checkEventLog(r.EventLog)
	s.checkComposeHash(nil)
	if s.computeConfigHash() {
		rep.pass(CheckConfigHash, "configHash = sha256(CJSON(config)) computed", map[string]any{"configHash": hex0x(s.configHash[:])})
	}
	if s.cfg != nil {
		if sameIDSet(s.cfg.releaseIDs, releaseIDs) {
			rep.pass(CheckConfigBinding, "releaseIds agree with the config", nil)
		} else {
			rep.failf(CheckConfigBinding, "releaseIds %s != config releases %s", idList(releaseIDs), idList(s.cfg.releaseIDs))
		}
	} else {
		rep.fail(CheckConfigBinding, "no config", nil)
	}

	var deploymentID [32]byte
	var customer common.Address
	if s.cfg != nil {
		customer = s.cfg.customer
		deploymentID = DeploymentID(customer, s.stackHash, s.cfg.salt)
		rep.DeploymentID = hex0x(deploymentID[:])
		rep.pass(CheckDeploymentID, "deploymentId = keccak256(abi.encode(customer, stackHash, salt)) derived", map[string]any{"derived": rep.DeploymentID})
	} else {
		rep.fail(CheckDeploymentID, "no config", nil)
	}

	s.checkReleases()
	s.checkRecompute(deploymentID)
	s.checkApproval()
	s.checkExpectedCustomer()
	if s.cfg != nil {
		var elh *[32]byte
		if canon, err := canonicalHash(r.EventLog); err == nil {
			elh = &canon
		}
		s.checkRecord(recordExpectation{
			deploymentID: deploymentID, customer: customer, stackHash: s.stackHash, imageID: imageID,
			configHash: s.configHash, enclaveSigner: signer, eventLogHashInfo: elh,
		})
	} else {
		rep.fail(CheckOnchainRecord, "no config", nil)
	}
	return rep.finish()
}
