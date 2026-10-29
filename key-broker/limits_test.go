package keybroker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
)

func postRelease(t testing.TB, url string, body []byte, hdr map[string]string) (int, keybroker.Denial, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/v1/release", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	var d keybroker.Denial
	_ = json.Unmarshal(raw, &d)
	return r.StatusCode, d, r.Header
}

func getNonce(t testing.TB, url string) [32]byte {
	t.Helper()
	r, err := http.Get(url + "/v1/nonce")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var nr keybroker.NonceResponse
	if err := json.NewDecoder(r.Body).Decode(&nr); err != nil {
		t.Fatalf("nonce: %d %v", r.StatusCode, err)
	}
	b, err := decodeHex(nr.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(b)
}

// TestDefaultBodyLimit (F1, D-066): the default limit is 2 MiB, refused before the body is read when the length is
// announced and while reading otherwise; a 2 MiB array of zeros (the memory exhaustion body) is junk, not a crash.
func TestDefaultBodyLimit(t *testing.T) {
	if keybroker.DefaultMaxBodyBytes != 2<<20 {
		t.Fatalf("DefaultMaxBodyBytes %d", keybroker.DefaultMaxBodyBytes)
	}
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	h := newHarness(t, w, harnessOpts{})
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{}))
	defer srv.Close()

	if st, _, _ := postRelease(t, srv.URL, bytes.Repeat([]byte(" "), keybroker.DefaultMaxBodyBytes+1), nil); st != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the limit: %d", st)
	}
	// Chunked (no Content-Length): refused while reading.
	pr, pw := io.Pipe()
	go func() {
		chunk := bytes.Repeat([]byte(" "), 64<<10)
		for i := 0; i < 40; i++ {
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/release", pr)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked over the limit: %d", r.StatusCode)
	}

	zeros := `{"config":[` + strings.Repeat("0,", (keybroker.DefaultMaxBodyBytes-32)/2) + `0]}`
	st, d, _ := postRelease(t, srv.URL, []byte(zeros), nil)
	if st != http.StatusForbidden || d.Reason != keybroker.ReasonBadNonce {
		t.Fatalf("zeros body: %d %+v", st, d)
	}
	h.flush(t)
	last := h.log.Last()
	if last == nil || !last.Truncated || len(last.Detail) > 210 {
		t.Fatalf("junk decision %+v", last)
	}
}

// slowLog blocks every write of a truncated (junk) decision until released.
type slowLog struct {
	keybroker.MemoryLog
	gate chan struct{}
}

func (s *slowLog) Write(ctx context.Context, d *keybroker.Decision) error {
	if d.Truncated {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.MemoryLog.Write(ctx, d)
}

// TestJunkDoesNotHoldSlots (F2, D-066): a slow body holds neither a release slot nor anything else of other
// requests, and junk requests are answered without waiting for the decision log, which takes them in the background
// in truncated form and counts what it had to drop. A real release goes through meanwhile.
func TestJunkDoesNotHoldSlots(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	sl := &slowLog{gate: make(chan struct{})}
	h := newHarness(t, w, harnessOpts{log: sl})
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{MaxInFlight: 1, ClientRate: -1}))
	defer srv.Close()

	// Scenario A: senders that announce a body and trickle it.
	host := strings.TrimPrefix(srv.URL, "http://")
	for range 3 {
		c, err := net.Dial("tcp", host)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "POST /v1/release HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{\"nonce\":")
	}
	// Scenario B: a flood of junk without a usable nonce, while the log is stuck.
	var wg sync.WaitGroup
	start := time.Now()
	for range 200 {
		wg.Go(func() {
			st, d, _ := postRelease(t, srv.URL, []byte(`{"nonce":"0x00"}`), nil)
			if st != http.StatusForbidden || d.Reason != keybroker.ReasonBadNonce {
				t.Errorf("junk: %d %+v", st, d)
			}
		})
	}
	wg.Wait()
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("junk answers waited for the log: %s", el)
	}
	// The real release still gets the one slot and its synchronous log entry.
	a := kbtest.NewAttempt(t, s, getNonce(t, srv.URL))
	st, d, _ := postRelease(t, srv.URL, a.Body(t), nil)
	if st != http.StatusOK {
		t.Fatalf("release during the flood: %d %+v", st, d)
	}
	close(sl.gate)
	h.flush(t)
	var junk int
	var suppressed uint64
	for _, d := range sl.All() {
		if d.Truncated {
			junk++
			for _, c := range d.Checks {
				if c.Data != nil || len(c.Detail) > 210 {
					t.Fatalf("junk check not truncated: %+v", c)
				}
			}
		}
		suppressed += d.Suppressed
	}
	if junk == 0 || junk > 70 || suppressed == 0 || uint64(junk)+suppressed < 200 {
		t.Fatalf("junk entries %d, suppressed %d: want a bounded queue that counts what it drops", junk, suppressed)
	}
}

// TestSlotTakenAfterAdmission (D-066): while every release slot is busy, a request with a bad nonce is still judged
// (403), and a well-formed one is shed with 429 rate_limited; its nonce is spent.
func TestSlotTakenAfterAdmission(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	bv := &blockingVerifier{started: make(chan struct{}, 4), release: make(chan struct{})}
	h := newHarness(t, w, harnessOpts{quotes: bv})
	s := w.Compose(t, kbtest.StackOptions{})
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{MaxInFlight: 1}))
	defer srv.Close()

	first := kbtest.NewAttempt(t, s, getNonce(t, srv.URL)).Body(t)
	done := make(chan struct{})
	go func() {
		postRelease(t, srv.URL, first, nil)
		close(done)
	}()
	select {
	case <-bv.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first release did not start")
	}
	if st, d, _ := postRelease(t, srv.URL, kbtest.NewAttempt(t, s, randomNonce(t)).Body(t), nil); st != http.StatusForbidden || d.Reason != keybroker.ReasonBadNonce {
		t.Fatalf("unknown nonce while busy: %d %+v", st, d)
	}
	shed := kbtest.NewAttempt(t, s, getNonce(t, srv.URL)).Body(t)
	st, d, hdr := postRelease(t, srv.URL, shed, nil)
	if st != http.StatusTooManyRequests || d.Reason != keybroker.ReasonRateLimited || hdr.Get("Retry-After") == "" {
		t.Fatalf("busy: %d %+v", st, d)
	}
	close(bv.release)
	<-done
	if st, d, _ := postRelease(t, srv.URL, shed, nil); st != http.StatusForbidden || d.Reason != keybroker.ReasonBadNonce {
		t.Fatalf("a shed request's nonce was reusable: %d %+v", st, d)
	}
}

// TestClientRateLimit (F2, F10, F9): one client address (the last X-Forwarded-For hop, which Cloud Run appends) gets
// its burst and then 429, whatever it puts in the earlier hops; another address is unaffected.
func TestClientRateLimit(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	h := newHarness(t, w, harnessOpts{})
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{ClientRate: 0.001, ClientBurst: 3}))
	defer srv.Close()

	from := func(i int, last string) map[string]string {
		return map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d, %s", i, last)}
	}
	for i := range 3 {
		if st, _, _ := postRelease(t, srv.URL, []byte(`x`), from(i, "203.0.113.9")); st != http.StatusBadRequest {
			t.Fatalf("request %d: %d", i, st)
		}
	}
	st, d, hdr := postRelease(t, srv.URL, []byte(`x`), from(99, "203.0.113.9"))
	if st != http.StatusTooManyRequests || d.Reason != keybroker.ReasonRateLimited || hdr.Get("Retry-After") == "" {
		t.Fatalf("over the burst: %d %+v", st, d)
	}
	if st, _, _ := postRelease(t, srv.URL, []byte(`x`), from(1, "203.0.113.10")); st != http.StatusBadRequest {
		t.Fatalf("another client: %d", st)
	}
	h.flush(t)
	if d := h.log.Last(); d == nil || d.Remote != "203.0.113.10" {
		t.Fatalf("decision remote %+v, want the last hop", d)
	}

	// Nonces have their own, larger bucket.
	n := 0
	for range 20 {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nonce", nil)
		req.Header.Set("X-Forwarded-For", "192.0.2.1")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			n++
		}
	}
	if n != 12 {
		t.Fatalf("%d nonces before 429, want 12 (4 x burst)", n)
	}
}
