package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCounterAggregatesPerCallerAndTotal(t *testing.T) {
	c := New(time.Unix(1730000000, 0), 0)
	c.Allow("scraper", "example.com:443")
	c.Allow("scraper", "example.com:443")
	c.Allow("agent", "example.com:443")
	c.Block("scraper", "*.evil.com:53")
	c.Block("(unknown)", "evil.com:443")

	s := c.Snapshot()
	if s.Since != 1730000000 {
		t.Errorf("since = %d", s.Since)
	}
	if s.Allowed["example.com:443"] != 3 {
		t.Errorf("total allowed = %v", s.Allowed)
	}
	if s.Callers["scraper"].Allowed["example.com:443"] != 2 || s.Callers["agent"].Allowed["example.com:443"] != 1 {
		t.Errorf("per caller allowed = %v", s.Callers)
	}
	if s.Blocked["*.evil.com:53"] != 1 || s.Blocked["evil.com:443"] != 1 || s.Blocked.Total() != 2 {
		t.Errorf("blocked = %v", s.Blocked)
	}
	if s.Callers["(unknown)"].Blocked["evil.com:443"] != 1 {
		t.Errorf("unknown caller not counted: %v", s.Callers)
	}
}

func TestCounterOverflow(t *testing.T) {
	c := New(time.Now(), 3)
	for i := 0; i < 10; i++ {
		c.Block("app", fmt.Sprintf("host%d.example:443", i))
	}
	c.Block("app", "host0.example:443") // existing keys keep counting
	b := c.Snapshot().Callers["app"].Blocked
	if len(b) != 4 {
		t.Fatalf("keys = %v, want 3 keys plus overflow", b)
	}
	if b[OverflowKey] != 7 || b["host0.example:443"] != 2 {
		t.Errorf("counts = %v", b)
	}
}

func TestTakeIntervalResets(t *testing.T) {
	c := New(time.Now(), 0)
	c.Allow("a", "x.example:443")
	first := c.TakeInterval(time.Now())
	if first.Allowed["x.example:443"] != 1 {
		t.Fatalf("interval = %v", first.Allowed)
	}
	if second := c.TakeInterval(time.Now()); len(second.Allowed) != 0 {
		t.Errorf("interval not reset: %v", second.Allowed)
	}
	if c.Snapshot().Allowed["x.example:443"] != 1 {
		t.Error("interval reset cleared the totals")
	}
}

func TestHandler(t *testing.T) {
	c := New(time.Unix(1730000000, 0), 0)
	c.Allow("a", "x.example:443")
	reader := netip.MustParseAddr("172.30.0.3")
	h := Handler(c, func(ap netip.AddrPort) bool { return ap.Addr() == reader })

	do := func(method, path, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodGet, "/v1/stats", "172.30.0.3:40000")
	if w.Code != http.StatusOK {
		t.Fatalf("reader got %d", w.Code)
	}
	var s Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Since != 1730000000 || s.Allowed["x.example:443"] != 1 || s.Callers["a"].Allowed["x.example:443"] != 1 {
		t.Errorf("snapshot = %+v", s)
	}
	for _, key := range []string{`"since"`, `"allowed"`, `"blocked"`, `"callers"`} {
		if !strings.Contains(w.Body.String(), key) {
			t.Errorf("body lacks %s: %s", key, w.Body.String())
		}
	}

	if w := do(http.MethodGet, "/v1/stats", "172.30.0.16:40000"); w.Code != http.StatusForbidden {
		t.Errorf("non-reader got %d", w.Code)
	}
	if w := do(http.MethodGet, "/v1/stats", "garbage"); w.Code != http.StatusForbidden {
		t.Errorf("unparseable remote got %d", w.Code)
	}
	if w := do(http.MethodPost, "/v1/stats", "172.30.0.3:40000"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST got %d", w.Code)
	}
	if w := do(http.MethodGet, "/healthz", "172.30.0.16:40000"); w.Code != http.StatusOK {
		t.Errorf("healthz got %d", w.Code)
	}
	if w := do(http.MethodGet, "/v1/other", "172.30.0.3:40000"); w.Code != http.StatusNotFound {
		t.Errorf("unknown path got %d", w.Code)
	}
}

func TestLogEveryWritesCountsOnly(t *testing.T) {
	c := New(time.Now(), 0)
	var buf syncBuffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { LogEvery(ctx, c, 20*time.Millisecond, log); close(done) }()
	c.Allow("scraper", "example.com:443")
	c.Block("scraper", "*.evil.com:443")
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("want several lines, got %q", buf.String())
	}
	var sawCounts, sawFinal bool
	for _, l := range lines {
		var rec struct {
			Msg     string                  `json:"msg"`
			Allowed uint64                  `json:"allowed"`
			Blocked uint64                  `json:"blocked"`
			Final   bool                    `json:"final"`
			Callers map[string]CallerCounts `json:"callers"`
		}
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		if rec.Msg != "egress counts" {
			t.Errorf("unexpected msg %q", rec.Msg)
		}
		if rec.Allowed == 1 && rec.Blocked == 1 && rec.Callers["scraper"].Blocked["*.evil.com:443"] == 1 {
			sawCounts = true
		}
		sawFinal = sawFinal || rec.Final
	}
	if !sawCounts || !sawFinal {
		t.Errorf("counts seen %v, final seen %v in %q", sawCounts, sawFinal, buf.String())
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
