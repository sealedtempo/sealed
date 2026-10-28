// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func frame(stream byte, payload string) []byte {
	b := make([]byte, 8, 8+len(payload))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
	return append(b, payload...)
}

func TestReadMultiplexed(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(1, "2026-10-28T12:00:00.000000001Z hello\n"))
	in.Write(frame(2, "2026-10-28T12:00:01Z oops\n"))
	in.Write(frame(1, "2026-10-28T12:00:02Z "+strings.Repeat("x", 100)+"\n"))
	var got []logLine
	if err := readMultiplexed(&in, 40, func(l logLine) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d lines", len(got))
	}
	if got[0].stream != "stdout" || got[0].text != "hello" || got[0].ts.Nanosecond() != 1 {
		t.Fatalf("line 0: %+v", got[0])
	}
	if got[1].stream != "stderr" || got[1].text != "oops" {
		t.Fatalf("line 1: %+v", got[1])
	}
	// The frame is cut at maxFrame bytes (timestamp included) and the rest of the frame is skipped.
	if len(got[2].text) != 40-len("2026-10-28T12:00:02Z ") {
		t.Fatalf("line 2 not truncated: %d", len(got[2].text))
	}
}

func TestReadMultiplexedTruncatedFrame(t *testing.T) {
	b := frame(1, "2026-10-28T12:00:00Z hello\n")
	if err := readMultiplexed(bytes.NewReader(b[:len(b)-3]), 1024, func(logLine) {}); err == nil {
		t.Fatal("a truncated frame must be an error")
	}
}

func TestReadRaw(t *testing.T) {
	in := strings.NewReader("2026-10-28T12:00:00Z one\r\n2026-10-28T12:00:01Z two\nno-timestamp")
	var got []logLine
	if err := readRaw(in, 1024, func(l logLine) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].text != "one" || got[1].text != "two" || got[2].text != "no-timestamp" {
		t.Fatalf("%+v", got)
	}
	if !got[2].ts.Equal(got[1].ts) {
		t.Fatal("a line without a timestamp keeps the previous time")
	}
}

func TestTruncateUTF8(t *testing.T) {
	if got := truncateUTF8("aé", 2); got != "a" {
		t.Fatalf("got %q", got)
	}
	if got := truncateUTF8("abc", 5); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

// fakeGCP serves the metadata server and Cloud Logging entries:write.
type fakeGCP struct {
	mu          sync.Mutex
	requests    []writeRequest
	auth        []string
	tokenCalls  int
	failWrites  int
	statusOnErr int
}

func (f *fakeGCP) handler() http.Handler {
	mux := http.NewServeMux()
	md := func(path, body string) {
		mux.HandleFunc("/computeMetadata/v1/"+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "missing header", http.StatusForbidden)
				return
			}
			io.WriteString(w, body)
		})
	}
	md("project/project-id", "customer-proj")
	md("instance/id", "1234567890")
	md("instance/zone", "projects/42/zones/us-central1-a")
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tokenCalls++
		n := f.tokenCalls
		f.mu.Unlock()
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600,"token_type":"Bearer"}`, n)
	})
	mux.HandleFunc("/v2/entries:write", func(w http.ResponseWriter, r *http.Request) {
		var req writeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failWrites > 0 {
			f.failWrites--
			http.Error(w, "unavailable", f.statusOnErr)
			return
		}
		f.requests = append(f.requests, req)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		io.WriteString(w, "{}")
	})
	return mux
}

func (f *fakeGCP) entries() []logEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []logEntry
	for _, r := range f.requests {
		out = append(out, r.Entries...)
	}
	return out
}

// fakeDocker serves one running container whose log stream is given per follow call.
type fakeDocker struct {
	mu      sync.Mutex
	streams [][]byte
	since   []string
}

func (d *fakeDocker) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.41/containers/json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"Id":"0123456789abcdef0123","Names":["/app-web-1"],"Image":"ghcr.io/x/web@sha256:00","Labels":{"com.docker.compose.service":"web","com.docker.compose.project":"app"}}]`)
	})
	mux.HandleFunc("/v1.41/containers/0123456789abcdef0123/json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Config":{"Tty":false}}`)
	})
	mux.HandleFunc("/v1.41/containers/0123456789abcdef0123/logs", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.since = append(d.since, r.URL.Query().Get("since"))
		var body []byte
		if len(d.streams) > 0 {
			body, d.streams = d.streams[0], d.streams[1:]
		}
		d.mu.Unlock()
		w.Write(body)
	})
	return mux
}

func testConfig(gcp, docker string) config {
	cfg := defaultConfig()
	cfg.dockerURL = docker
	cfg.metadataURL = gcp + "/computeMetadata/v1"
	cfg.loggingURL = gcp + "/v2/entries:write"
	cfg.pollInterval = 20 * time.Millisecond
	cfg.flushInterval = 20 * time.Millisecond
	cfg.maxBackoff = 50 * time.Millisecond
	return cfg
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunShipsContainerLogs(t *testing.T) {
	gcp := &fakeGCP{statusOnErr: http.StatusServiceUnavailable, failWrites: 1}
	gs := httptest.NewServer(gcp.handler())
	defer gs.Close()
	var first, second bytes.Buffer
	first.Write(frame(1, "2026-10-28T12:00:00Z started\n"))
	first.Write(frame(2, "2026-10-28T12:00:01Z warning on stderr\n"))
	// After the container restarts Docker replays from since (inclusive): the repeated line must be skipped.
	second.Write(frame(2, "2026-10-28T12:00:01Z warning on stderr\n"))
	second.Write(frame(1, "2026-10-28T12:00:05Z restarted\n"))
	dk := &fakeDocker{streams: [][]byte{first.Bytes(), second.Bytes()}}
	ds := httptest.NewServer(dk.handler())
	defer ds.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, testConfig(gs.URL, ds.URL), &syncWriter{w: &logs}) }()
	waitFor(t, func() bool { return len(gcp.entries()) >= 3 })
	cancel()
	<-done

	got := gcp.entries()
	texts := []string{}
	for _, e := range got {
		texts = append(texts, e.TextPayload)
	}
	if strings.Join(texts[:3], "|") != "started|warning on stderr|restarted" {
		t.Fatalf("entries: %q", texts)
	}
	e := got[1]
	if e.Labels["stream"] != "stderr" || e.Labels["container_name"] != "app-web-1" || e.Labels["compose_service"] != "web" ||
		e.Labels["compose_project"] != "app" || e.Labels["container_id"] != "0123456789ab" {
		t.Fatalf("labels: %v", e.Labels)
	}
	if e.Timestamp != "2026-10-28T12:00:01Z" || e.InsertID == "" || e.InsertID == got[0].InsertID {
		t.Fatalf("entry: %+v", e)
	}
	gcp.mu.Lock()
	req := gcp.requests[0]
	auth := gcp.auth[0]
	tokens := gcp.tokenCalls
	gcp.mu.Unlock()
	if req.LogName != "projects/customer-proj/logs/sealed-debug-containers" || req.Resource.Type != "gce_instance" ||
		req.Resource.Labels["zone"] != "us-central1-a" || req.Resource.Labels["instance_id"] != "1234567890" || !req.PartialSuccess {
		t.Fatalf("request: %+v", req)
	}
	if auth != "Bearer tok-1" || tokens != 1 {
		t.Fatalf("token reuse: auth %q after %d token calls", auth, tokens)
	}
	dk.mu.Lock()
	since := append([]string(nil), dk.since...)
	dk.mu.Unlock()
	if len(since) < 2 || since[0] != "" || since[1] != "1793188801.000000000" {
		t.Fatalf("since: %q", since)
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func TestSinkBoundedBufferReportsDrops(t *testing.T) {
	gcp := &fakeGCP{}
	gs := httptest.NewServer(gcp.handler())
	defer gs.Close()
	cfg := testConfig(gs.URL, "")
	cfg.maxBuffer = 3
	cfg.maxBatch = 2
	md := &metadataClient{base: cfg.metadataURL, http: gs.Client()}
	s := newSink(cfg, resource{ProjectID: "p", InstanceID: "1", Zone: "z"}, md, gs.Client(), newLimitedLog(io.Discard, time.Minute))
	ts := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.add("c", logLine{stream: "stdout", ts: ts.Add(time.Duration(i) * time.Second), text: fmt.Sprint(i)}, nil)
	}
	if err := s.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, e := range gcp.entries() {
		texts = append(texts, e.TextPayload)
	}
	want := "sealed-logship dropped 2 container log lines while Cloud Logging was unreachable|2|3|4"
	if strings.Join(texts, "|") != want {
		t.Fatalf("got %q", texts)
	}
	if s.pending() != 0 {
		t.Fatalf("pending %d", s.pending())
	}
}

func TestSinkCommitAfterConcurrentDrop(t *testing.T) {
	cfg := defaultConfig()
	cfg.maxBuffer = 3
	s := newSink(cfg, resource{}, nil, nil, newLimitedLog(io.Discard, time.Minute))
	ts := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		s.add("c", logLine{ts: ts, text: fmt.Sprint(i)}, nil)
	}
	_, last, _ := s.take()                      // batch 0,1,2 in flight
	s.add("c", logLine{ts: ts, text: "3"}, nil) // drops 0
	s.commit(last, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) != 1 || s.buf[0].TextPayload != "3" {
		t.Fatalf("buffer after commit: %+v", s.buf)
	}
}

func TestSinkRejectedBatchIsDropped(t *testing.T) {
	gcp := &fakeGCP{failWrites: 1, statusOnErr: http.StatusBadRequest}
	gs := httptest.NewServer(gcp.handler())
	defer gs.Close()
	cfg := testConfig(gs.URL, "")
	md := &metadataClient{base: cfg.metadataURL, http: gs.Client()}
	var logs bytes.Buffer
	s := newSink(cfg, resource{ProjectID: "p"}, md, gs.Client(), newLimitedLog(&logs, time.Minute))
	s.add("c", logLine{ts: time.Now(), text: "x"}, nil)
	if err := s.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.pending() != 0 || !strings.Contains(logs.String(), "rejected") {
		t.Fatalf("pending %d, log %q", s.pending(), logs.String())
	}
}

func TestNoServiceAccount(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	md := &metadataClient{base: srv.URL, http: srv.Client()}
	if _, err := md.accessToken(context.Background()); err != errNoServiceAccount {
		t.Fatalf("got %v", err)
	}
}

func TestLimitedLog(t *testing.T) {
	var b bytes.Buffer
	l := newLimitedLog(&b, time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	l.printf("k", "one")
	l.printf("k", "two")
	now = now.Add(2 * time.Minute)
	l.printf("k", "three")
	if b.String() != "sealed-logship: one\nsealed-logship: three\n" {
		t.Fatalf("%q", b.String())
	}
}

func TestUnreadableLogsAreHeldBack(t *testing.T) {
	gcp := &fakeGCP{}
	gs := httptest.NewServer(gcp.handler())
	defer gs.Close()
	var mu sync.Mutex
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.41/containers/json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"Id":"c1","Names":["/quiet"],"Image":"x","Labels":{}}]`)
	})
	mux.HandleFunc("/v1.41/containers/c1/json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Config":{"Tty":false}}`)
	})
	mux.HandleFunc("/v1.41/containers/c1/logs", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, `{"message":"configured logging driver does not support reading"}`, http.StatusNotImplemented)
	})
	ds := httptest.NewServer(mux)
	defer ds.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	var logs bytes.Buffer
	run(ctx, testConfig(gs.URL, ds.URL), &syncWriter{w: &logs})
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("logs requested %d times; an unreadable container must be held back", calls)
	}
	if !strings.Contains(logs.String(), "HTTP 501") {
		t.Fatalf("log %q", logs.String())
	}
}
