package keybroker

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Queue sizes of the asynchronous decision log (D-066). Denials of requests that got past the request checks have
// their own queue, so a flood of junk can only crowd out junk.
const (
	denialQueueSize = 256
	junkQueueSize   = 64
)

// MaxLogBatch bounds the decisions of one background write when the decision log takes batches (BatchLog).
const MaxLogBatch = 32

// logQueue writes decisions that do not gate an answer in the background, so a slow Cloud Logging never holds a
// release slot or a request: junk, and denials and errors of requests whose quote did not verify or did not carry
// this request's report_data. Allowed releases and denials past report_data are not queued (writeNow): no flood of
// junk or replayed quotes can crowd them out (kb-6).
type logQueue struct {
	log     DecisionLog
	op      *slog.Logger
	timeout time.Duration
	// batch is how many queued decisions one write takes: MaxLogBatch when log is a BatchLog, else 1.
	batch int

	denials chan *Decision
	junk    chan *Decision
	stop    chan struct{}
	done    chan struct{}

	mu         sync.Mutex
	cond       *sync.Cond
	closed     bool
	pending    int    // queued, not yet written
	suppressed uint64 // dropped since the last written entry
	dropped    uint64 // dropped in total
	lastWarn   time.Time
}

func newLogQueue(log DecisionLog, op *slog.Logger, timeout time.Duration) *logQueue {
	q := &logQueue{log: log, op: op, timeout: timeout, batch: 1, denials: make(chan *Decision, denialQueueSize),
		junk: make(chan *Decision, junkQueueSize), stop: make(chan struct{}), done: make(chan struct{})}
	if _, ok := log.(BatchLog); ok {
		q.batch = MaxLogBatch
	}
	q.cond = sync.NewCond(&q.mu)
	go q.run()
	return q
}

// enqueue queues d without blocking. A full queue drops it and counts it; the next written entry carries the count.
func (q *logQueue) enqueue(d *Decision, junk bool) {
	ch := q.denials
	if junk {
		ch = q.junk
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	select {
	case ch <- d:
		q.pending++
		q.mu.Unlock()
		return
	default:
	}
	q.suppressed++
	q.dropped++
	warn := time.Since(q.lastWarn) > time.Minute
	if warn {
		q.lastWarn = time.Now()
	}
	total := q.dropped
	q.mu.Unlock()
	if warn {
		q.op.Warn("decision log queue full; decisions dropped", "droppedTotal", total, "junk", junk)
	}
}

func (q *logQueue) run() {
	defer close(q.done)
	for {
		d, ok := q.next(true)
		if !ok {
			return
		}
		batch := []*Decision{d}
		for len(batch) < q.batch {
			d, ok := q.next(false)
			if !ok {
				break
			}
			batch = append(batch, d)
		}
		q.write(batch)
	}
}

// next takes a queued decision, denials first. With wait it blocks until one is queued; once the queue is stopped it
// returns false when both channels are empty.
func (q *logQueue) next(wait bool) (*Decision, bool) {
	select {
	case d := <-q.denials:
		return d, true
	default:
	}
	select {
	case d := <-q.denials:
		return d, true
	case d := <-q.junk:
		return d, true
	default:
	}
	if !wait {
		return nil, false
	}
	select {
	case d := <-q.denials:
		return d, true
	case d := <-q.junk:
		return d, true
	case <-q.stop:
		select {
		case d := <-q.denials:
			return d, true
		case d := <-q.junk:
			return d, true
		default:
			return nil, false
		}
	}
}

// takeSuppressed hands the count of dropped decisions to the next entry written.
func (q *logQueue) takeSuppressed(d *Decision) {
	q.mu.Lock()
	d.Suppressed, q.suppressed = q.suppressed, 0
	q.mu.Unlock()
}

func (q *logQueue) write(batch []*Decision) {
	q.takeSuppressed(batch[0])
	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	var err error
	if bl, ok := q.log.(BatchLog); ok && len(batch) > 1 {
		err = bl.WriteBatch(ctx, batch)
	} else {
		err = q.log.Write(ctx, batch[0])
	}
	cancel()
	if err != nil {
		for _, d := range batch {
			q.op.Error("decision log write failed", "err", err, "requestId", d.RequestID, "decision", d.Decision, "reason", d.Reason)
		}
	}
	q.mu.Lock()
	q.pending -= len(batch)
	q.cond.Broadcast()
	q.mu.Unlock()
}

// writeNow writes d before returning, for a denial or error of a request past report_data: its TDX quote verified and
// binds this request's nonce and ephemeral key (kb-6). Such attempts need a live TDX VM, so they are few, and their
// entry must not be dropped by a full queue. A replayed quote fails report_data and never comes here. The answer waits
// for the write but does not depend on it: a failed write is reported on the operational log, and the denial stands.
func (q *logQueue) writeNow(ctx context.Context, d *Decision) {
	q.takeSuppressed(d)
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), q.timeout)
	err := q.log.Write(lctx, d)
	cancel()
	if err != nil {
		q.op.Error("decision log write failed", "err", err, "requestId", d.RequestID, "decision", d.Decision, "reason", d.Reason)
	}
}

// flush waits until every queued decision was written, or ctx ends.
func (q *logQueue) flush(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		q.mu.Lock()
		for q.pending > 0 {
			q.cond.Wait()
		}
		q.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// close stops accepting decisions and waits until the queued ones were written, or ctx ends.
func (q *logQueue) close(ctx context.Context) error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.stop)
	}
	q.mu.Unlock()
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
