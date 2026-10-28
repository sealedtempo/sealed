// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

type monitoredResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type logEntry struct {
	InsertID    string            `json:"insertId"`
	Timestamp   string            `json:"timestamp"`
	Severity    string            `json:"severity,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	TextPayload string            `json:"textPayload"`

	size  int    // approximate encoded size, not sent
	seqNo uint64 // position in the buffer order, not sent
}

type writeRequest struct {
	LogName        string            `json:"logName"`
	Resource       monitoredResource `json:"resource"`
	Entries        []logEntry        `json:"entries"`
	PartialSuccess bool              `json:"partialSuccess"`
}

// sink buffers entries and writes them to Cloud Logging in batches. The buffer is bounded: while the API is
// unreachable the oldest lines are dropped and counted, and a warning entry reports the count once writes work.
type sink struct {
	cfg  config
	res  resource
	md   *metadataClient
	http *http.Client
	log  *limitedLog

	mu      sync.Mutex
	buf     []logEntry
	dropped int
	seq     uint64
	kick    chan struct{}
}

func newSink(cfg config, res resource, md *metadataClient, hc *http.Client, lg *limitedLog) *sink {
	return &sink{cfg: cfg, res: res, md: md, http: hc, log: lg, kick: make(chan struct{}, 1)}
}

// truncateUTF8 cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func (s *sink) add(containerID string, l logLine, base map[string]string) {
	labels := make(map[string]string, len(base)+1)
	for k, v := range base {
		labels[k] = v
	}
	labels["stream"] = l.stream
	text := truncateUTF8(l.text, s.cfg.maxLineBytes)
	s.mu.Lock()
	s.seq++
	e := logEntry{
		InsertID:    fmt.Sprintf("%s-%d-%d", shortID(containerID), l.ts.UnixNano(), s.seq),
		Timestamp:   l.ts.UTC().Format(time.RFC3339Nano),
		Labels:      labels,
		TextPayload: text,
		size:        len(text) + 256,
		seqNo:       s.seq,
	}
	if len(s.buf) >= s.cfg.maxBuffer {
		n := len(s.buf) - s.cfg.maxBuffer + 1
		s.buf = append(s.buf[:0], s.buf[n:]...)
		s.dropped += n
	}
	s.buf = append(s.buf, e)
	full := len(s.buf) >= s.cfg.maxBatch
	s.mu.Unlock()
	if full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

// take returns the next batch without removing it, prefixed by a drop warning when lines were lost. last is the
// sequence number of the newest buffered entry in the batch.
func (s *sink) take() (batch []logEntry, last uint64, dropped int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	size, n := 0, 0
	for n < len(s.buf) && n < s.cfg.maxBatch && (n == 0 || size+s.buf[n].size <= s.cfg.maxBatchBytes) {
		size += s.buf[n].size
		n++
	}
	batch = append(batch, s.buf[:n]...)
	if n > 0 {
		last = s.buf[n-1].seqNo
	}
	dropped = s.dropped
	if dropped > 0 {
		s.seq++
		warn := logEntry{
			InsertID:    fmt.Sprintf("sealed-logship-dropped-%d", s.seq),
			Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
			Severity:    "WARNING",
			Labels:      map[string]string{"source": "sealed-logship"},
			TextPayload: fmt.Sprintf("sealed-logship dropped %d container log lines while Cloud Logging was unreachable", dropped),
		}
		batch = append([]logEntry{warn}, batch...)
	}
	return batch, last, dropped
}

// commit removes the entries up to and including sequence number last. Entries are matched by sequence number,
// not position, because add may have dropped the oldest entries while the batch was in flight.
func (s *sink) commit(last uint64, dropped int) {
	s.mu.Lock()
	i := 0
	for i < len(s.buf) && s.buf[i].seqNo <= last {
		i++
	}
	s.buf = append(s.buf[:0], s.buf[i:]...)
	s.dropped -= dropped
	s.mu.Unlock()
}

func (s *sink) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf) + s.dropped
}

func (s *sink) loop(ctx context.Context) {
	tick := time.NewTicker(s.cfg.flushInterval)
	defer tick.Stop()
	backoff := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			// Best effort: one last write so the final lines of a stopping VM are not lost.
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.flush(fctx)
			cancel()
			return
		case <-tick.C:
		case <-s.kick:
		}
		if backoff > 0 && !sleepCtx(ctx, backoff) {
			continue
		}
		if err := s.flush(ctx); err != nil {
			if ctx.Err() != nil {
				continue
			}
			s.log.printf("write", "writing to Cloud Logging: %v", err)
			if backoff == 0 {
				backoff = time.Second
			} else {
				backoff = minDuration(backoff*2, s.cfg.maxBackoff)
			}
			continue
		}
		backoff = 0
	}
}

// flush writes batches until the buffer is empty or a write fails.
func (s *sink) flush(ctx context.Context) error {
	for s.pending() > 0 {
		batch, last, dropped := s.take()
		if len(batch) == 0 {
			return nil
		}
		permanent, err := s.write(ctx, batch)
		if err != nil && !permanent {
			return err
		}
		if err != nil {
			// The API refused the batch itself (HTTP 400): retrying cannot help, so drop it rather than wedge.
			s.log.printf("rejected", "Cloud Logging rejected a batch of %d entries, dropping it: %v", len(batch), err)
		}
		s.commit(last, dropped)
	}
	return nil
}

// write sends one entries:write request. permanent reports a rejection that retrying cannot fix.
func (s *sink) write(ctx context.Context, batch []logEntry) (permanent bool, err error) {
	token, err := s.md.accessToken(ctx)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(writeRequest{
		LogName: "projects/" + s.res.ProjectID + "/logs/" + s.cfg.logName,
		Resource: monitoredResource{Type: "gce_instance", Labels: map[string]string{
			"project_id":  s.res.ProjectID,
			"instance_id": s.res.InstanceID,
			"zone":        s.res.Zone,
		}},
		Entries:        batch,
		PartialSuccess: true,
	})
	if err != nil {
		return true, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.loggingURL, bytes.NewReader(body))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusOK:
		return false, nil
	case resp.StatusCode == http.StatusUnauthorized:
		s.md.invalidate()
		return false, fmt.Errorf("HTTP 401: %s", bytes.TrimSpace(msg))
	case resp.StatusCode == http.StatusBadRequest:
		return true, fmt.Errorf("HTTP 400: %s", bytes.TrimSpace(msg))
	default:
		return false, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
}
