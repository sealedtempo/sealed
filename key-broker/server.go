package keybroker

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// DefaultMaxBodyBytes bounds a POST /v1/release body. app-compose.json of a five-app stack is about 100 KiB; the
// hex-encoded quote is under 20 KiB.
const DefaultMaxBodyBytes = 16 << 20

// ServerOptions configure the HTTP API.
type ServerOptions struct {
	// MaxInFlight bounds concurrent releases; more answer 429 with Retry-After. 0 means 8.
	MaxInFlight int
	// MaxBodyBytes bounds a release body; 0 means DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Handler serves GET /v1/nonce, POST /v1/release and GET /healthz (INTERFACES.md section 9).
func (b *Broker) Handler(o ServerOptions) http.Handler {
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = 8
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	slots := make(chan struct{}, o.MaxInFlight)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		resp, err := b.IssueNonce()
		if err != nil {
			b.deps.OpLog.Error("issue nonce", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, &Denial{Decision: DecisionError, Reason: ReasonUnavailable, Detail: "no nonce available"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /v1/release", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "2")
			writeJSON(w, http.StatusTooManyRequests, &Denial{Decision: DecisionError, Reason: ReasonUnavailable, Detail: "too many releases in flight"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, o.MaxBodyBytes))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeJSON(w, http.StatusRequestEntityTooLarge, &Denial{Decision: DecisionDenied, Reason: ReasonBadRequest, Detail: "body too large"})
				return
			}
			writeJSON(w, http.StatusBadRequest, &Denial{Decision: DecisionDenied, Reason: ReasonBadRequest, Detail: "could not read body"})
			return
		}
		out := b.Release(r.Context(), body, remoteAddr(r))
		w.Header().Set("X-Request-Id", out.Decision.RequestID)
		writeJSON(w, out.Status, out.Body)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// remoteAddr is the caller as seen by Cloud Run's front end (the first X-Forwarded-For hop), for the decision log
// only. It never drives a decision.
func remoteAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
