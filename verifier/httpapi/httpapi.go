// Package httpapi is the HTTP interface of sealed-verifierd:
//
//	POST /v1/verify/evidence  evidence bundle, or {"bundle": {...}, "options": {...}}  -> Report
//	POST /v1/verify/live      {"url": "https://attest.../attest", "options": {...}}  -> Report
//	POST /v1/compose          {"config": {...}} or a bare config -> {appCompose, stackHash, configHash, deploymentId}
//	GET  /healthz
//
// Verification results are always HTTP 200 with the report (check "ok"); 400 means the request itself was
// unusable. Add ?format=text for the human-readable report.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// MaxBodyBytes bounds request bodies (an evidence bundle with a full compose is well under 1 MiB).
const MaxBodyBytes = 8 << 20

// Server serves the verifier API.
type Server struct {
	Deps verify.Deps
	// ChainID is the chain every verification is pinned to (4217 on mainnet).
	ChainID uint64
	// LiveInsecureTLS skips WebPKI checks of /attest certificates (dev only; the key binding is still checked).
	LiveInsecureTLS bool
	// LiveTimeout bounds a live attestation round trip.
	LiveTimeout time.Duration
	// VerifyTimeout bounds one verification.
	VerifyTimeout time.Duration
	Log           *slog.Logger
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/verify/evidence", s.verifyEvidence)
	mux.HandleFunc("POST /v1/verify/live", s.verifyLive)
	mux.HandleFunc("POST /v1/compose", s.compose)
	mux.HandleFunc("GET /healthz", s.healthz)
	return mux
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
}

func (s *Server) verifyLive(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req liveRequest
	if err := json.Unmarshal(body, &req); err != nil || req.URL == "" {
		writeError(w, http.StatusBadRequest, `body must be {"url": "https://.../attest", "options": {...}}`)
		return
	}
	opts, err := s.options(req.Options)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	rep, err := verify.VerifyLive(ctx, req.URL, s.Deps, verify.LiveOptions{Options: opts, Timeout: s.LiveTimeout, InsecureSkipTLSVerify: s.LiveInsecureTLS})
	if err != nil {
		s.log().Error("verify live", "err", err)
		writeError(w, http.StatusInternalServerError, "verifier misconfigured")
		return
	}
	s.log().Info("verified live attestation", "deploymentId", rep.DeploymentID, "ok", rep.OK, "simulated", rep.Simulated, "failed", rep.Failed())
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
