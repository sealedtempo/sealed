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

// logQueue writes decisions that do not gate an answer (every denial and error) in the background, so a slow
// Cloud Logging never holds a release slot or a request. Allowed releases are not queued: they are answered only
// after their entry was written.
type logQueue struct {
	log     DecisionLog
	op      *slog.Logger
	timeout time.Duration

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
	q := &logQueue{log: log, op: op, timeout: timeout, denials: make(chan *Decision, denialQueueSize),
		junk: make(chan *Decision, junkQueueSize), stop: make(chan struct{}), done: make(chan struct{})}
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
		select { // denials first
		case d := <-q.denials:
			q.write(d)
			continue
		default:
		}
		select {
		case d := <-q.denials:
			q.write(d)
		case d := <-q.junk:
			q.write(d)
		case <-q.stop:
			for {
				select {
				case d := <-q.denials:
					q.write(d)
				case d := <-q.junk:
					q.write(d)
				default:
					return
				}
			}
		}
	}
}

func (q *logQueue) write(d *Decision) {
	q.mu.Lock()
	d.Suppressed, q.suppressed = q.suppressed, 0
	q.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	err := q.log.Write(ctx, d)
	cancel()
	if err != nil {
		q.op.Error("decision log write failed", "err", err, "requestId", d.RequestID, "decision", d.Decision, "reason", d.Reason)
	}
	q.mu.Lock()
	q.pending--
	q.cond.Broadcast()
	q.mu.Unlock()
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
