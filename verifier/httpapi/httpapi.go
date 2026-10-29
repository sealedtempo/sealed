// Package httpapi is the HTTP interface of sealed-verifierd:
//
//	POST /v1/verify/evidence  evidence bundle, or {"bundle": {...}, "options": {...}}  -> Report
//	POST /v1/verify/live      {"url": "https://attest.../attest", "options": {...}}  -> Report
//	                          or a caller-fetched attestation: {"attestUrl", "nonce", "attest": {...},
//	                          "observedTlsPubKeyHash", "expectedCustomer", "expectedAppIds", "options"}
//	POST /v1/compose          {"config": {...}} or a bare config -> {appCompose, stackHash, configHash, deploymentId, unbuilt?}
//	GET  /healthz             {ok, chainId, allowSimulated, composer, composerVersion, liveFetch, maxBodyBytes}
//
// Verification results are always HTTP 200 with the report (check "ok"); 400 means the request itself was
// unusable, 403 that the caller's address is not an allowed client (or that this server does not fetch attest URLs),
// 413 that the body is larger than MaxBodyBytes (8 MiB; {"error", "code": "body_too_large", "limitBytes"}, before a
// slot is taken when Content-Length says so) and 429 that MaxInFlight verifications are already running. Add
// ?format=text for the human-readable report.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/bundles"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
)

// MaxBodyBytes bounds request bodies: 8 MiB (8388608 bytes). An evidence bundle with a full compose is well under
// 1 MiB. Callers that forward bodies here (the platform api's /v1/evidence and /v1/verify, and Caddy in front of
// it) must not accept more, or a body between the two limits passes them and fails here; /healthz reports the
// value as maxBodyBytes.
const MaxBodyBytes = 8 << 20

// bodyTooLarge is the 413 answer: the limit in words and in bytes, so a caller can tell it from other failures.
func bodyTooLarge(w http.ResponseWriter) {
	writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
		"error":      fmt.Sprintf("request body is larger than %d MiB (%d bytes), the sealed-verifierd limit", MaxBodyBytes>>20, MaxBodyBytes),
		"code":       "body_too_large",
		"limitBytes": MaxBodyBytes,
	})
}

// DefaultMaxInFlight bounds concurrent verifications and compositions. Each one makes about ten RPC calls and may
// fetch Intel PCS collateral or an /attest document.
const DefaultMaxInFlight = 8

// Server serves the verifier API.
type Server struct {
	Deps verify.Deps
	// ChainID is the chain every verification is pinned to (4217 on mainnet).
	ChainID uint64
	// LiveInsecureTLS skips WebPKI checks of /attest certificates (dev only; the key binding is still checked).
	LiveInsecureTLS bool
	// LiveAllowedHosts, when non-empty, restricts the attest URLs this server fetches ("*.sslip.io", relay host).
	LiveAllowedHosts []string
	// LiveAllowPrivate lets live fetches connect to non-public addresses (dev only).
	LiveAllowPrivate bool
	// LiveTimeout bounds a live attestation round trip.
	LiveTimeout time.Duration
	// VerifyTimeout bounds one verification.
	VerifyTimeout time.Duration
	// MaxInFlight bounds concurrent verifications and compositions; 0 means DefaultMaxInFlight.
	MaxInFlight int
	// AllowedClients, when non-empty, are the only source addresses served (D-061: in a stack, the payer's
	// address). The TCP peer address is used, never a forwarded header. Loopback may also call GET /healthz.
	AllowedClients []netip.Prefix
	// DisableLiveFetch refuses POST /v1/verify/live with a URL, so the server never fetches for a caller; only
	// caller-fetched attestations are verified (the in-CVM sidecar, review V-1).
	DisableLiveFetch bool
	// MaxChainHeadAge bounds the age of the head block of every verification (D-060); 0 means the library default.
	MaxChainHeadAge time.Duration
	Log             *slog.Logger

	slotsOnce sync.Once
	slots     chan struct{}
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/verify/evidence", s.limited(s.verifyEvidence))
	mux.HandleFunc("POST /v1/verify/live", s.limited(s.verifyLive))
	mux.HandleFunc("POST /v1/compose", s.limited(s.compose))
	mux.HandleFunc("GET /healthz", s.healthz)
	if len(s.AllowedClients) == 0 {
		return mux
	}
	return s.clientsOnly(mux)
}

// clientsOnly serves only requests whose TCP peer is in AllowedClients (D-061), before any body is read or a slot
// is taken. Loopback (the daemon's own container) may also read GET /healthz.
func (s *Server) clientsOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, ok := peerAddr(r)
		if ok && (s.allowedClient(addr) || (addr.IsLoopback() && r.Method == http.MethodGet && r.URL.Path == "/healthz")) {
			next.ServeHTTP(w, r)
			return
		}
		s.log().Warn("refused request from a source that is not an allowed client", "remote", r.RemoteAddr, "path", r.URL.Path)
		writeError(w, http.StatusForbidden, "this verifier serves only its configured clients")
	})
}

func (s *Server) allowedClient(a netip.Addr) bool {
	for _, p := range s.AllowedClients {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerAddr is the request's TCP peer address (r.RemoteAddr), with IPv4-mapped IPv6 addresses unmapped.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ParseClients parses a comma-separated list of IP addresses and CIDR prefixes (--allowed-clients).
func ParseClients(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			if p != p.Masked() {
				return nil, fmt.Errorf("client prefix %q has host bits set (use %s)", item, p.Masked())
			}
			if p.Addr().Is4In6() && p.Bits() < 96 {
				return nil, fmt.Errorf("client prefix %q is wider than the IPv4-mapped range", item)
			}
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr())))
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("invalid client address %q (an IP address or a CIDR prefix)", item)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// unmapBits is 96 for an IPv4-mapped IPv6 address, whose prefix length shrinks by 96 bits once unmapped.
func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

// limited runs h only when one of MaxInFlight slots is free, and answers 429 otherwise: the API is unauthenticated,
// so callers must not be able to queue unbounded work against the RPC, Intel PCS or attest hosts. A body that
// Content-Length already shows to be over MaxBodyBytes is refused first, without a slot.
func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxBodyBytes {
			s.log().Warn("refused an oversized body", "path", r.URL.Path, "contentLength", r.ContentLength, "limitBytes", MaxBodyBytes)
			bodyTooLarge(w)
			return
		}
		s.slotsOnce.Do(func() {
			n := s.MaxInFlight
			if n <= 0 {
				n = DefaultMaxInFlight
			}
			s.slots = make(chan struct{}, n)
		})
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
			h(w, r)
		default:
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "too many verifications in flight, retry later")
		}
	}
}

// RequestOptions are the per-request verification options.
type RequestOptions struct {
	// RequireRecord fails when the deployment is not registered. Default true; the oracle sets false before it
	// registers a new deployment.
	RequireRecord *bool `json:"requireRecord,omitempty"`
	// MaxEvidenceAgeSeconds bounds now - attestedAt (the oracle uses 900).
	MaxEvidenceAgeSeconds int64 `json:"maxEvidenceAgeSeconds,omitempty"`
	// DeploymentID must equal the bundle's deployment id when set.
	DeploymentID string `json:"deploymentId,omitempty"`
	// ExpectedCustomer must equal config.customer when set (for example the operator for the relay).
	ExpectedCustomer string `json:"expectedCustomer,omitempty"`
	// ExpectedAppIDs must all be among config.apps[].id when set.
	ExpectedAppIDs []string `json:"expectedAppIds,omitempty"`
	// Heartbeat verifies evidence for DeploymentRegistry.heartbeat (a new quote for a registered deployment).
	Heartbeat bool `json:"heartbeat,omitempty"`
}

func (s *Server) options(o RequestOptions) (verify.Options, error) {
	// A simulated quote can only pass on a dev daemon (--dev-allow-simulated with SEALED_DEV_SIM=1). Such a daemon
	// opts in for every request; its consumers (the payer, the oracle) refuse simulated reports themselves unless
	// they run in dev mode too, and every such report says simulated.
	opts := verify.Options{
		ChainID: s.ChainID, RequireOnchainRecord: true, MaxChainHeadAge: s.MaxChainHeadAge,
		AcceptSimulated: s.Deps.Quotes != nil && s.Deps.Quotes.AllowsSimulated(),
	}
	if o.RequireRecord != nil {
		opts.RequireOnchainRecord = *o.RequireRecord
	}
	if o.MaxEvidenceAgeSeconds < 0 {
		return opts, errors.New("maxEvidenceAgeSeconds must not be negative")
	}
	opts.MaxEvidenceAge = time.Duration(o.MaxEvidenceAgeSeconds) * time.Second
	if o.DeploymentID != "" {
		id, err := hexb.Decode32(o.DeploymentID)
		if err != nil {
			return opts, fmt.Errorf("deploymentId: %w", err)
		}
		opts.ExpectedDeploymentID = &id
	}
	if o.ExpectedCustomer != "" {
		b, err := hexb.Decode20(o.ExpectedCustomer)
		if err != nil {
			return opts, fmt.Errorf("expectedCustomer: %w", err)
		}
		addr := common.Address(b)
		opts.ExpectedCustomer = &addr
	}
	for _, id := range o.ExpectedAppIDs {
		if id == "" {
			return opts, errors.New("expectedAppIds: empty id")
		}
	}
	opts.ExpectedAppIDs = o.ExpectedAppIDs
	opts.Heartbeat = o.Heartbeat
	return opts, nil
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	d := s.VerifyTimeout
	if d <= 0 {
		d = 2 * time.Minute
	}
	return context.WithTimeout(r.Context(), d)
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		bodyTooLarge(w)
		return nil, false
	case err != nil:
		writeError(w, http.StatusBadRequest, "request body unreadable: "+err.Error())
		return nil, false
	}
	return body, true
}

type evidenceRequest struct {
	Bundle  json.RawMessage `json:"bundle"`
	Options RequestOptions  `json:"options"`
}

func (s *Server) verifyEvidence(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		writeError(w, http.StatusBadRequest, "body is not JSON: "+err.Error())
		return
	}
	req := evidenceRequest{Bundle: body}
	if probe.Schema == "" {
		req = evidenceRequest{}
		if err := json.Unmarshal(body, &req); err != nil || len(req.Bundle) == 0 {
			writeError(w, http.StatusBadRequest, `body must be an evidence bundle or {"bundle": ..., "options": ...}`)
			return
		}
	}
	opts, err := s.options(req.Options)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	rep, err := verify.VerifyEvidenceJSON(ctx, req.Bundle, s.Deps, opts)
	if err != nil {
		s.log().Error("verify evidence", "err", err)
		writeError(w, http.StatusInternalServerError, "verifier misconfigured")
		return
	}
	s.log().Info("verified evidence", "deploymentId", rep.DeploymentID, "ok", rep.OK, "simulated", rep.Simulated, "failed", rep.Failed())
	writeReport(w, r, rep)
}

type liveRequest struct {
	URL     string         `json:"url"`
	Options RequestOptions `json:"options"`

	// A caller-fetched attestation (sealed-mpp-payer): the document, the caller's nonce and the SPKI hash of the
	// certificate it observed. ExpectedCustomer and ExpectedAppIDs may also be given here instead of in options.
	AttestURL             string          `json:"attestUrl"`
	Nonce                 string          `json:"nonce"`
	Attest                json.RawMessage `json:"attest"`
	ObservedTLSPubKeyHash string          `json:"observedTlsPubKeyHash"`
	ExpectedCustomer      string          `json:"expectedCustomer"`
	ExpectedAppIDs        []string        `json:"expectedAppIds"`
}

func (s *Server) verifyLive(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req liveRequest
	if err := json.Unmarshal(body, &req); err != nil || (req.URL == "" && len(req.Attest) == 0) {
		writeError(w, http.StatusBadRequest, `body must be {"url": "https://.../attest", "options": {...}} or a caller-fetched attestation {"nonce", "attest", "observedTlsPubKeyHash", ...}`)
		return
	}
	if req.ExpectedCustomer != "" {
		if req.Options.ExpectedCustomer != "" && req.Options.ExpectedCustomer != req.ExpectedCustomer {
			writeError(w, http.StatusBadRequest, "expectedCustomer and options.expectedCustomer differ")
			return
		}
		req.Options.ExpectedCustomer = req.ExpectedCustomer
	}
	req.Options.ExpectedAppIDs = append(req.Options.ExpectedAppIDs, req.ExpectedAppIDs...)
	opts, err := s.options(req.Options)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	var rep *verify.Report
	if len(req.Attest) > 0 {
		sub := verify.LiveSubmission{AttestURL: req.AttestURL, Attest: req.Attest}
		var nErr, kErr error
		sub.Nonce, nErr = hexb.Decode32(req.Nonce)
		sub.ObservedTLSPubKeyHash, kErr = hexb.Decode32(req.ObservedTLSPubKeyHash)
		if err := errors.Join(nErr, kErr); err != nil {
			writeError(w, http.StatusBadRequest, "nonce and observedTlsPubKeyHash must be 32-byte hex: "+err.Error())
			return
		}
		rep, err = verify.VerifyLiveSubmission(ctx, sub, s.Deps, opts)
	} else {
		if s.DisableLiveFetch {
			writeError(w, http.StatusForbidden, `this verifier does not fetch attest URLs; send a caller-fetched attestation {"nonce", "attest", "observedTlsPubKeyHash", ...}`)
			return
		}
		rep, err = verify.VerifyLive(ctx, req.URL, s.Deps, verify.LiveOptions{
			Options: opts, Timeout: s.LiveTimeout, InsecureSkipTLSVerify: s.LiveInsecureTLS,
			AllowedHosts: s.LiveAllowedHosts, AllowPrivateAddresses: s.LiveAllowPrivate,
		})
	}
	if err != nil {
		s.log().Error("verify live", "err", err)
		writeError(w, http.StatusInternalServerError, "verifier misconfigured")
		return
	}
	s.log().Info("verified live attestation", "mode", rep.Mode, "deploymentId", rep.DeploymentID, "ok", rep.OK, "simulated", rep.Simulated, "failed", rep.Failed())
	writeReport(w, r, rep)
}

type composeResponse struct {
	AppCompose   string `json:"appCompose"`
	StackHash    string `json:"stackHash"`
	ConfigHash   string `json:"configHash"`
	DeploymentID string `json:"deploymentId"`
	// Unbuilt lists images still at the all-zero placeholder digest; such a stack cannot boot and must not be
	// approved. Omitted when every image is built.
	Unbuilt []string `json:"unbuilt,omitempty"`
}

func (s *Server) compose(w http.ResponseWriter, r *http.Request) {
	if s.Deps.Composer == nil {
		writeError(w, http.StatusNotImplemented, "composer not configured on this server")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var wrapped struct {
		Config json.RawMessage `json:"config"`
	}
	cfg := json.RawMessage(body)
	if err := json.Unmarshal(body, &wrapped); err != nil {
		writeError(w, http.StatusBadRequest, "body is not JSON")
		return
	}
	if len(wrapped.Config) > 0 {
		cfg = wrapped.Config
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	out, err := verify.ComposeFromChain(ctx, s.Deps, cfg)
	if errors.Is(err, bundles.ErrUnavailable) {
		// The release assets could not be fetched (catalog host down): retryable, unlike a bad config.
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, composeResponse{
		AppCompose: string(out.AppCompose), StackHash: hexb.Enc(out.StackHash[:]),
		ConfigHash: hexb.Enc(out.ConfigHash[:]), DeploymentID: hexb.Enc(out.DeploymentID[:]), Unbuilt: out.Unbuilt,
	})
}

// ComposerVersion is the composerVersion configs must name for this server's composer: the runtime/composer
// version a bundles.Composer recomputes with, empty when the composer does not say (or none is wired).
func (s *Server) ComposerVersion() string {
	if v, ok := s.Deps.Composer.(interface{ ComposerVersion() string }); ok {
		return v.ComposerVersion()
	}
	return ""
}

// healthz reports what callers need to talk to this server: the chain, whether simulated quotes pass, whether a
// composer is wired and the composerVersion configs must name (the platform api writes it into new configs), whether
// attest URLs are fetched, and the body limit.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"chainId":         s.ChainID,
		"allowSimulated":  s.Deps.Quotes != nil && s.Deps.Quotes.AllowsSimulated(),
		"composer":        s.Deps.Composer != nil,
		"composerVersion": s.ComposerVersion(),
		"liveFetch":       !s.DisableLiveFetch,
		"maxBodyBytes":    MaxBodyBytes,
	})
}

func writeReport(w http.ResponseWriter, r *http.Request, rep *verify.Report) {
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = rep.WriteText(w)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
