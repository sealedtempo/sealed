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

	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
	"github.com/sealedtempo/sealed/verifier/internal/strictjson"
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
	// AllowedHosts, when non-empty, restricts attest URLs to these hosts: exact names or addresses, or "*.domain"
	// for any name below domain (for example "*.sslip.io" and the relay's host).
	AllowedHosts []string
	// AllowPrivateAddresses lets the fetch connect to loopback, private, link-local and other non-public addresses,
	// on any port (dev only). Otherwise every resolved destination must be public, unless the request goes through
	// the HTTPS_PROXY from the environment, and the port must be 443.
	AllowPrivateAddresses bool
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

// AttestPath is the only path a live verification fetches: sealed-agent's GET /attest (INTERFACES.md section 11).
const AttestPath = "/attest"

// checkAttestURL accepts exactly https://<host>[:443]/attest. The verifier adds the nonce itself, so a caller
// cannot choose the path, the query, credentials or (outside dev runs) the port: inside a CVM the fetch goes out
// through sealed-egress under the verifier's own egress rule, and a caller-chosen path or query would turn the
// verifier into an HTTP client for whoever can reach its API (review V-1).
func checkAttestURL(u *url.URL, opts LiveOptions) error {
	switch {
	case u.Scheme != "https":
		return errors.New("attest URL must be https (the TLS key binding needs a TLS connection)")
	case u.Opaque != "" || u.Host == "" || u.Hostname() == "":
		return errors.New("attest URL has no host")
	case u.User != nil:
		return errors.New("attest URL must not carry credentials")
	case u.Path != AttestPath || u.RawPath != "":
		return fmt.Errorf("attest URL path must be %s, not %q", AttestPath, u.EscapedPath())
	case u.RawQuery != "" || u.ForceQuery:
		return errors.New("attest URL must not carry a query: the verifier sends its own nonce")
	case u.Fragment != "" || u.RawFragment != "":
		return errors.New("attest URL must not carry a fragment")
	case u.Port() != "" && u.Port() != "443" && !opts.AllowPrivateAddresses:
		return fmt.Errorf("attest URL port must be 443, not %s", u.Port())
	case !hostAllowed(u.Hostname(), opts.AllowedHosts):
		return fmt.Errorf("attest host %q is not one of the allowed hosts %v", u.Hostname(), opts.AllowedHosts)
	}
	return nil
}

func fetchAttest(ctx context.Context, attestURL string, opts LiveOptions) (*fetched, error) {
	u, err := url.Parse(attestURL)
	if err != nil {
		return nil, fmt.Errorf("attest URL: %w", err)
	}
	if err := checkAttestURL(u, opts); err != nil {
		return nil, err
	}
	f := &fetched{}
	if _, err := rand.Read(f.nonce[:]); err != nil {
		return nil, err
	}
	u.RawQuery = url.Values{"nonce": {hex0x(f.nonce[:])}}.Encode()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs, InsecureSkipVerify: opts.InsecureSkipTLSVerify} // #nosec G402 -- dev flag; the key binding is checked below
	tr, err := liveTransport(req, tlsConf, opts.AllowPrivateAddresses)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: tr,
		// A redirect would move the request to another connection; refuse it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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
	if f.resp, err = decodeAttest(body); err != nil {
		return nil, err
	}
	return f, nil
}

// decodeAttest decodes a GET /attest document with case-sensitive, unique keys.
func decodeAttest(body []byte) (liveResponse, error) {
	var r liveResponse
	if err := strictjson.Unmarshal(body, &r); err != nil {
		return r, fmt.Errorf("decode /attest: %w", err)
	}
	// dstack-style APIs return the event log as a JSON string; accept both shapes.
	var inner string
	if json.Unmarshal(r.EventLog, &inner) == nil {
		if err := strictjson.CheckKeys([]byte(inner), nil); err != nil {
			return r, fmt.Errorf("decode /attest eventLog: %w", err)
		}
		r.EventLog = json.RawMessage(inner)
	}
	return r, nil
}

// LiveSubmission is a live attestation the caller fetched itself (sealed-mpp-payer checking the relay): its own
// nonce, the GET /attest document and the SPKI hash of the certificate it saw on that connection.
type LiveSubmission struct {
	AttestURL             string
	Nonce                 [32]byte
	ObservedTLSPubKeyHash [32]byte
	Attest                json.RawMessage
}

// VerifyLiveSubmission verifies a live attestation fetched by the caller. The verifier makes no connection, so
// freshness and the TLS key binding are relative to the nonce and key the caller reports: only a caller that
// generated the nonce and observed the key itself learns anything about liveness. Every stack check is the same
// as in VerifyLive. The report mode is ModeLiveSubmitted.
func VerifyLiveSubmission(ctx context.Context, sub LiveSubmission, deps Deps, opts Options) (*Report, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	rep := newReport(ModeLiveSubmitted, deps.now())
	data := map[string]any{"url": sub.AttestURL, "nonce": hex0x(sub.Nonce[:]), "observedTlsPubKeyHash": hex0x(sub.ObservedTLSPubKeyHash[:])}
	resp, err := decodeAttest(sub.Attest)
	if err != nil {
		rep.fail(CheckLiveFetch, err.Error(), data)
		return rep.finish(), nil
	}
	rep.pass(CheckLiveFetch, "attestation submitted by the caller; nonce and TLS key are as the caller observed them", data)
	f := &fetched{nonce: sub.Nonce, servedSPKI: sub.ObservedTLSPubKeyHash, resp: resp}
	return verifyLiveResponse(ctx, f, deps, opts, rep), nil
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

	s := &session{ctx: ctx, deps: deps, chain: deps.Chain, opts: opts, rep: rep, cfgRaw: r.Config, appCompose: []byte(r.AppCompose)}
	s.stackHash = sha256.Sum256(s.appCompose)
	rep.StackHash = hex0x(s.stackHash[:])
	cfg, err := parseConfig(r.Config)
	if err != nil {
		rep.failf(CheckBundle, "config: %v", err)
	} else {
		s.cfg = cfg
		rep.Config = cfg.summary()
		rep.pass(CheckBundle, fmt.Sprintf("/attest response with %d releases", len(releaseIDs)), nil)
	}

	if tlsHash != f.servedSPKI {
		rep.fail(CheckTLSBinding, "tlsPubKeyHash is not the SPKI hash of the certificate served on the /attest connection", map[string]any{
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
		detail := fmt.Sprintf("fresh: our nonce is bound, answered in %s", f.elapsed.Round(time.Millisecond))
		if rep.Mode == ModeLiveSubmitted {
			detail = "the caller's nonce is bound (freshness as observed by the caller)"
		}
		rep.pass(CheckFreshness, detail, map[string]any{"nonce": hex0x(f.nonce[:])})
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
		deploymentID = s.checkLiveDeploymentID()
	} else {
		rep.fail(CheckDeploymentID, "no config", nil)
	}

	s.checkReleases()
	s.checkRecompute(deploymentID)
	s.checkApproval()
	s.checkExpectedCustomer()
	s.checkExpectedApps()
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

// checkLiveDeploymentID derives the deployment id of the served stack and compares it with
// Options.ExpectedDeploymentID, so a caller pinning a deployment never accepts another deployment's attestation.
func (s *session) checkLiveDeploymentID() [32]byte {
	derived := DeploymentID(s.cfg.customer, s.stackHash, s.cfg.salt)
	s.rep.DeploymentID = hex0x(derived[:])
	data := map[string]any{"derived": s.rep.DeploymentID}
	if want := s.opts.ExpectedDeploymentID; want != nil && *want != derived {
		data["expected"] = hex0x(want[:])
		s.rep.fail(CheckDeploymentID, fmt.Sprintf("served stack is deployment %s, expected %s", s.rep.DeploymentID, hex0x(want[:])), data)
		return derived
	}
	detail := "deploymentId = keccak256(abi.encode(customer, stackHash, salt)) derived"
	if s.opts.ExpectedDeploymentID != nil {
		detail += ", the expected deployment"
	}
	s.rep.pass(CheckDeploymentID, detail, data)
	return derived
}
