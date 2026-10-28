package keybroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// DefaultMaxBodyBytes bounds a POST /v1/release body (D-066). app-compose.json of a five-app stack is about 100 KiB
// (twice that once escaped inside the JSON body), the hex quote under 20 KiB, a Sealed event log a few KiB to tens of
// KiB, a config at most 128 KiB.
const DefaultMaxBodyBytes = 2 << 20

// Server limits (D-066).
const (
	// DefaultMaxInFlight bounds the releases that run their checks at the same time.
	DefaultMaxInFlight = 8
	// DefaultMaxParsing bounds the bodies parsed at the same time; parsing is the only work before the nonce check.
	DefaultMaxParsing = 4
	// DefaultBodyReadTimeout bounds reading one body; a slow sender holds only its own connection, never a slot.
	DefaultBodyReadTimeout = 10 * time.Second
	// DefaultReleaseTimeout bounds the checks of one release (it covers the bundle fetches of a cold start).
	DefaultReleaseTimeout = 90 * time.Second
	// DefaultLogTimeout bounds writing one decision; an allowed release waits for its entry.
	DefaultLogTimeout = 15 * time.Second
	// MaxRequestDuration is the longest one release request takes: its body read, its checks and its log entry.
	// The Cloud Run request timeout of the bootstrap must be at least this (TestBootstrapCloudRunLimits).
	MaxRequestDuration = DefaultBodyReadTimeout + DefaultReleaseTimeout + DefaultLogTimeout
	// DefaultClientRate and DefaultClientBurst bound release requests per client address; nonce requests get four
	// times as much. A booting agent needs one nonce and one release per attempt and retries after a second or more.
	DefaultClientRate  = 2.0
	DefaultClientBurst = 20
	// maxClients bounds the limiter's table.
	maxClients = 16384
)

// ServerOptions configure the HTTP API.
type ServerOptions struct {
	// MaxInFlight bounds concurrent releases; more answer 429 with Retry-After. 0 means DefaultMaxInFlight.
	MaxInFlight int
	// MaxParsing bounds concurrent body parsing; 0 means DefaultMaxParsing.
	MaxParsing int
	// MaxBodyBytes bounds a release body; 0 means DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// BodyReadTimeout bounds reading a release body; 0 means DefaultBodyReadTimeout.
	BodyReadTimeout time.Duration
	// ClientRate is release requests per second per client address (nonce requests: four times this); 0 means
	// DefaultClientRate, a negative value turns the per-client limit off.
	ClientRate float64
	// ClientBurst is the bucket size per client address; 0 means DefaultClientBurst.
	ClientBurst int
}

// Handler serves GET /v1/nonce, POST /v1/release and GET /healthz (INTERFACES.md section 9).
//
// A release runs in this order, so unauthenticated work stays bounded (D-066): the per-client limit; the body read
// with its own deadline and size limit, before any slot; parsing, the nonce check and request validation under the
// parse limit; only then a release slot for the attestation and approval checks. Denials are logged in the
// background (junk truncated); an allowed release waits for its log entry after giving its slot back.
func (b *Broker) Handler(o ServerOptions) http.Handler {
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = DefaultMaxInFlight
	}
	if o.MaxParsing <= 0 {
		o.MaxParsing = DefaultMaxParsing
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.BodyReadTimeout <= 0 {
		o.BodyReadTimeout = DefaultBodyReadTimeout
	}
	if o.ClientRate == 0 {
		o.ClientRate = DefaultClientRate
	}
	if o.ClientBurst <= 0 {
		o.ClientBurst = DefaultClientBurst
	}
	releaseLimit := newClientLimiter(o.ClientRate, o.ClientBurst, maxClients, nil)
	nonceLimit := newClientLimiter(4*o.ClientRate, 4*o.ClientBurst, maxClients, nil)
	slots := make(chan struct{}, o.MaxInFlight)
	parsing := make(chan struct{}, o.MaxParsing)

	tooMany := func(w http.ResponseWriter, detail string) {
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, &Denial{Decision: DecisionError, Reason: ReasonRateLimited, Detail: detail})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		if !nonceLimit.allow(limitKey(clientAddr(r))) {
			tooMany(w, "too many nonce requests from this address")
			return
		}
		resp, err := b.IssueNonce()
		if err != nil {
			b.deps.OpLog.Error("issue nonce", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, &Denial{Decision: DecisionError, Reason: ReasonUnavailable, Detail: "no nonce available"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /v1/release", func(w http.ResponseWriter, r *http.Request) {
		remote := clientAddr(r)
		if !releaseLimit.allow(limitKey(remote)) {
			tooMany(w, "too many release requests from this address")
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(o.BodyReadTimeout))
		body, err := readBody(w, r, o.MaxBodyBytes)
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeJSON(w, http.StatusRequestEntityTooLarge, &Denial{Decision: DecisionDenied, Reason: ReasonBadRequest, Detail: "body too large"})
				return
			}
			writeJSON(w, http.StatusBadRequest, &Denial{Decision: DecisionDenied, Reason: ReasonBadRequest, Detail: "could not read body"})
			return
		}

		wait := time.NewTimer(5 * time.Second)
		select {
		case parsing <- struct{}{}:
			wait.Stop()
		case <-wait.C:
			tooMany(w, "too many requests being parsed")
			return
		case <-r.Context().Done():
			wait.Stop()
			return
		}
		s, st := b.admit(body, remote)
		<-parsing
		body = nil

		var resp *ReleaseResponse
		if st == nil {
			select {
			case slots <- struct{}{}:
				resp, st = s.check(r.Context())
				<-slots
			default:
				st = s.shed("too many releases in flight")
			}
		}
		out := b.finish(r.Context(), s, resp, st)
		w.Header().Set("X-Request-Id", out.Decision.RequestID)
		if out.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(out.RetryAfter))
		}
		writeJSON(w, out.Status, out.Body)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

// readBody reads at most max bytes, sized up front from Content-Length when it is within the limit.
func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	if r.ContentLength > max {
		return nil, &http.MaxBytesError{Limit: max}
	}
	var buf bytes.Buffer
	if r.ContentLength > 0 {
		buf.Grow(int(r.ContentLength) + 1)
	}
	_, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
