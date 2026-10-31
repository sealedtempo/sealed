package keybroker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/attest"
)

// gatedLog holds every write of a decision with the given reason until gate is closed; other decisions are written
// at once.
type gatedLog struct {
	keybroker.MemoryLog
	reason string
	gate   chan struct{}
}

func (g *gatedLog) Write(ctx context.Context, d *keybroker.Decision) error {
	if d.Reason == g.reason {
		select {
		case <-g.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return g.MemoryLog.Write(ctx, d)
}

// syncBuf is a bytes.Buffer safe for the concurrent writes of a slog handler.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// floodBroker is a broker over w with the given decision log and a JSON op log, sharing h's bundles, nonces and clock.
func floodBroker(t *testing.T, w *kbtest.World, h *harness, dlog keybroker.DecisionLog, op *syncBuf) *keybroker.Broker {
	t.Helper()
	src, err := keybroker.NewHTTPBundleSource(keybroker.HTTPBundleSourceOptions{Base: h.bundles.Base()})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := keybroker.NewLocalHMAC(w.MACKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keybroker.New(keybroker.Config{Customer: kbtest.Customer, ChainID: w.Reg.ChainID(), Contracts: w.Reg.Contracts(),
		FeeSplitter: kbtest.FeeSplitter, FeeToken: kbtest.FeeToken, AllowSimulated: true},
		keybroker.Deps{Nonces: h.nonces, Quotes: simVerifier(t), Chain: w.Reg.Chain(), Bundles: src, Secrets: w.Secrets, MAC: mac,
			Log: dlog, OpLog: slog.New(slog.NewJSONHandler(op, nil)), Now: h.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// junkQuoteFlood sends n well-formed requests whose quotes do not verify. They are admitted (their nonces are real),
// so they are full denials, not junk, and they go to the background queue.
func junkQuoteFlood(t *testing.T, b *keybroker.Broker, s *kbtest.Stack, n int) {
	t.Helper()
	bodies := make([][]byte, n)
	for i := range bodies {
		r, err := b.IssueNonce()
		if err != nil {
			t.Fatal(err)
		}
		nb, err := decodeHex(r.Nonce)
		if err != nil {
			t.Fatal(err)
		}
		a := kbtest.NewAttempt(t, s, [32]byte(nb))
		a.Quote = bytes.Repeat([]byte{0x04}, 700)
		bodies[i] = a.Body(t)
	}
	var wg sync.WaitGroup
	for _, body := range bodies {
		wg.Go(func() { b.Release(context.Background(), body, "198.51.100.9") })
	}
	wg.Wait()
}

// TestDenialFloodKeepsAttestedDenial (kb-6): a flood of well-formed requests with junk quotes fills the background
// queue behind a stuck decision log. A later denial of an attempt whose TDX quote verified (an unapproved stack) is
// written before its answer, so the flood cannot drop it, and its operational log line carries the attempt's hashes,
// customer and remote. Ported from the verifier's TestKBVerifyDenialFloodDropsRealDenial, which found the real
// attempt missing from the decision log.
func TestDenialFloodKeepsAttestedDenial(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	ok := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, ok)
	never := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) { c.Salt = "0x" + strings.Repeat("01", 32) }})

	h := newHarness(t, w, harnessOpts{})
	dlog := &gatedLog{reason: keybroker.ReasonQuoteInvalid, gate: make(chan struct{})}
	var op syncBuf
	b := floodBroker(t, w, h, dlog, &op)
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(dlog.gate) }) }
	defer b.Close(context.Background())
	defer openGate() // before Close, also when the test fails early

	const flood = 600
	junkQuoteFlood(t, b, ok, flood)
	if !strings.Contains(op.String(), "decision log queue full") {
		t.Fatal("the flood did not fill the queue; the test does not exercise kb-6")
	}

	// h's broker shares the nonce store.
	real := kbtest.NewAttempt(t, never, h.nonce(t))
	out := b.Release(context.Background(), real.Body(t), "203.0.113.66")
	expectDenied(t, out, 403, keybroker.ReasonStackNotApproved)

	// The entry is there before the stuck writes go through, and it is complete.
	var got *keybroker.Decision
	for _, d := range dlog.All() {
		if d.RequestID == out.Decision.RequestID {
			got = d
		}
	}
	if got == nil {
		t.Fatalf("the attested denial %s is not in the decision log", out.Decision.RequestID)
	}
	if got.Truncated || got.Remote != "203.0.113.66" || got.Hashes.QuoteHash == "" || got.Hashes.MeasurementsHash == "" ||
		got.Hashes.StackHash != never.Result.StackHash.Hex() || len(got.Checks) == 0 {
		t.Fatalf("entry %+v", got)
	}
	if got.Suppressed == 0 {
		t.Fatal("the entry does not carry the count of dropped decisions")
	}

	var line map[string]any
	for _, l := range strings.Split(op.String(), "\n") {
		if strings.Contains(l, out.Decision.RequestID) && strings.Contains(l, "release decision") {
			if err := json.Unmarshal([]byte(l), &line); err != nil {
				t.Fatal(err)
			}
		}
	}
	h2 := out.Decision.Hashes
	for k, want := range map[string]string{"quoteHash": h2.QuoteHash, "measurementsHash": h2.MeasurementsHash, "eventLogHash": h2.EventLogHash,
		"deploymentId": h2.DeploymentID, "customer": h2.Customer, "remote": "203.0.113.66", "stackHash": h2.StackHash} {
		if want == "" || line[k] != want {
			t.Errorf("op log %s = %v, want %q", k, line[k], want)
		}
	}

	openGate()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestReplayedQuoteDenialIsQueued (kb-6 repair): VerifyQuote checks no freshness, so anyone holding one captured
// genuine quote can replay it with a fresh nonce. The replay passes the quote check and fails report_data, without
// any TDX VM. Its denial must go to the background queue, not the synchronous write: with a stuck decision log the
// answer comes at once, and the entry is written once the log moves again. On the old code (writeNow for every
// verified quote) the answer waited for the log write, up to DefaultLogTimeout.
func TestReplayedQuoteDenialIsQueued(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	h := newHarness(t, w, harnessOpts{})
	dlog := &gatedLog{reason: keybroker.ReasonReportDataMismatch, gate: make(chan struct{})}
	var op syncBuf
	b := floodBroker(t, w, h, dlog, &op)
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(dlog.gate) }) }
	defer b.Close(context.Background())
	defer openGate()

	// A genuine quote captured from another release attempt: it verifies, but binds another nonce.
	a := kbtest.NewAttempt(t, s, h.nonce(t))
	a.Quote = kbtest.SimQuoteFor(t, a.Events, attest.KeyReleaseReportData(randomNonce(t), a.Pub), false, nil)
	started := time.Now()
	out := b.Release(context.Background(), a.Body(t), "203.0.113.67")
	took := time.Since(started)
	expectDenied(t, out, 403, keybroker.ReasonReportDataMismatch)
	if took > 3*time.Second {
		t.Fatalf("the replayed quote's denial waited %s for the stuck decision log; it must be queued", took)
	}
	if len(dlog.All()) != 0 {
		t.Fatal("the denial was written before the answer")
	}

	openGate()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var got *keybroker.Decision
	for _, d := range dlog.All() {
		if d.RequestID == out.Decision.RequestID {
			got = d
		}
	}
	if got == nil || got.Truncated || got.Hashes.QuoteHash == "" {
		t.Fatalf("queued entry %+v", got)
	}
}

// batchLog records how decisions arrive: one Write per decision, or batches. Its first call blocks until gate is
// closed, so the queue fills behind it.
type batchLog struct {
	keybroker.MemoryLog
	gate    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	batches []int
}

func (l *batchLog) wait() { l.once.Do(func() { <-l.gate }) }

func (l *batchLog) Write(ctx context.Context, d *keybroker.Decision) error {
	l.wait()
	l.mu.Lock()
	l.batches = append(l.batches, 1)
	l.mu.Unlock()
	return l.MemoryLog.Write(ctx, d)
}

func (l *batchLog) WriteBatch(ctx context.Context, ds []*keybroker.Decision) error {
	l.wait()
	l.mu.Lock()
	l.batches = append(l.batches, len(ds))
	l.mu.Unlock()
	for _, d := range ds {
		if err := l.MemoryLog.Write(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

// TestDecisionQueueBatches (kb-6): when the decision log takes batches (Cloud Logging entries:write), the background
// queue drains in batches of at most keybroker.MaxLogBatch, so a backlog costs a few calls instead of one per entry.
// Every queued decision is written, and written entries plus the dropped count add up to the flood.
func TestDecisionQueueBatches(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	h := newHarness(t, w, harnessOpts{})
	dlog := &batchLog{gate: make(chan struct{})}
	var op syncBuf
	b := floodBroker(t, w, h, dlog, &op)
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(dlog.gate) }) }
	defer b.Close(context.Background())
	defer openGate()

	const flood = 400
	junkQuoteFlood(t, b, s, flood)
	openGate()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	all := dlog.All()
	var suppressed uint64
	for _, d := range all {
		suppressed += d.Suppressed
	}
	dlog.mu.Lock()
	batches := append([]int(nil), dlog.batches...)
	dlog.mu.Unlock()
	max := 0
	for _, n := range batches {
		max = maxInt(max, n)
		if n > keybroker.MaxLogBatch {
			t.Fatalf("batch of %d, more than %d", n, keybroker.MaxLogBatch)
		}
	}
	if max < 2 || len(batches) > len(all)/2 {
		t.Fatalf("%d calls for %d entries (largest batch %d): the queue did not batch", len(batches), len(all), max)
	}
	if uint64(len(all))+suppressed != flood {
		t.Fatalf("%d written + %d dropped, want %d", len(all), suppressed, flood)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
