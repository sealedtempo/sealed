// Package httpapi is the HTTP interface of sealed-verifierd:
//
//	POST /v1/verify/evidence  evidence bundle, or {"bundle": {...}, "options": {...}}  -> Report
//	POST /v1/verify/live      {"url": "https://attest.../attest", "options": {...}}  -> Report
//	                          or a caller-fetched attestation: {"attestUrl", "nonce", "attest": {...},
//	                          "observedTlsPubKeyHash", "expectedCustomer", "expectedAppIds", "options"}
//	POST /v1/compose          {"config": {...}} or a bare config -> {appCompose, stackHash, configHash, deploymentId}
//	GET  /healthz
//
// Verification results are always HTTP 200 with the report (check "ok"); 400 means the request itself was
// unusable and 429 that MaxInFlight verifications are already running. Add ?format=text for the human-readable
// report.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// MaxBodyBytes bounds request bodies (an evidence bundle with a full compose is well under 1 MiB).
const MaxBodyBytes = 8 << 20

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
	Log         *slog.Logger

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
	return mux
}

// limited runs h only when one of MaxInFlight slots is free, and answers 429 otherwise: the API is unauthenticated,
// so callers must not be able to queue unbounded work against the RPC, Intel PCS or attest hosts.
func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	opts := verify.Options{ChainID: s.ChainID, RequireOnchainRecord: true}
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
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large or unreadable")
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
}

func (s *Server) compose(w http.ResponseWriter, r *http.Request) {
	if s.Deps.Composer == nil {
		writeError(w, http.StatusNotImplemented, "composer not wired into this build (runtime/composer)")
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
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, composeResponse{
		AppCompose: string(out.AppCompose), StackHash: hexb.Enc(out.StackHash[:]),
		ConfigHash: hexb.Enc(out.ConfigHash[:]), DeploymentID: hexb.Enc(out.DeploymentID[:]),
	})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"chainId":        s.ChainID,
		"allowSimulated": s.Deps.Quotes != nil && s.Deps.Quotes.AllowsSimulated(),
		"composer":       s.Deps.Composer != nil,
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
