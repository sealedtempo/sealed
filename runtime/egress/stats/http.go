package stats

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

// Handler serves GET /v1/stats to callers whose source passes isReader, and
// GET /healthz to anyone (it carries no data).
func Handler(c *Counter, isReader func(remote netip.AddrPort) bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		remote, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !isReader(remote) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, c.Snapshot())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// LogEvery writes one log line with the interval's counts every interval
// until ctx ends, then a final line. Only counts and destination keys are
// logged.
func LogEvery(ctx context.Context, c *Counter, interval time.Duration, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	start := time.Now()
	emit := func(final bool) {
		now := time.Now()
		s := c.TakeInterval(start)
		log.Info("egress counts",
			"interval_s", int64(now.Sub(start).Round(time.Second)/time.Second),
			"allowed", s.Allowed.Total(),
			"blocked", s.Blocked.Total(),
			"callers", s.Callers,
			"final", final,
		)
		start = now
	}
	for {
		select {
		case <-ctx.Done():
			emit(true)
			return
		case <-t.C:
			emit(false)
		}
	}
}
