// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// dockerAPI is the API version used for every call. Docker 20.10 and later serve it.
const dockerAPI = "/v1.41"

type dockerClient struct {
	base string
	http *http.Client
}

func newDockerClient(socket, baseURL string) *dockerClient {
	if baseURL != "" {
		return &dockerClient{base: strings.TrimRight(baseURL, "/"), http: &http.Client{}}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &dockerClient{base: "http://docker", http: &http.Client{Transport: tr}}
}

type containerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

func (c *dockerClient) getJSON(ctx context.Context, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+dockerAPI+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

// running lists the running containers.
func (c *dockerClient) running(ctx context.Context) ([]containerSummary, error) {
	var list []containerSummary
	err := c.getJSON(ctx, "/containers/json", &list)
	return list, err
}

// tty reports whether the container has a TTY, which decides the log stream format.
func (c *dockerClient) tty(ctx context.Context, id string) (bool, error) {
	var info struct {
		Config struct {
			Tty bool `json:"Tty"`
		} `json:"Config"`
	}
	err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/json", &info)
	return info.Config.Tty, err
}

// follow opens the log stream of a container from since (exclusive) on. It ends when the container stops.
func (c *dockerClient) follow(ctx context.Context, id string, since time.Time) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("follow", "1")
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("timestamps", "1")
	if !since.IsZero() {
		q.Set("since", fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond()))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+dockerAPI+"/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("docker logs %s: HTTP %d", shortID(id), resp.StatusCode)
	}
	return resp.Body, nil
}

// logLine is one container log line as Docker returns it with timestamps=1.
type logLine struct {
	stream string
	ts     time.Time
	text   string
}

// splitTimestamp splits "2026-10-28T12:00:00.123456789Z message" into its parts. Lines without a parsable
// timestamp keep the previous line's time.
func splitTimestamp(s string, prev time.Time) (time.Time, string) {
	if i := strings.IndexByte(s, ' '); i > 0 {
		if t, err := time.Parse(time.RFC3339Nano, s[:i]); err == nil {
			return t, s[i+1:]
		}
	}
	if prev.IsZero() {
		prev = time.Now().UTC()
	}
	return prev, s
}

func streamName(b byte) string {
	switch b {
	case 1:
		return "stdout"
	case 2:
		return "stderr"
	default:
		return "system"
	}
}

// readMultiplexed parses Docker's multiplexed log stream (containers without a TTY): frames with an 8-byte
// header {stream, 0, 0, 0, size uint32 big endian} followed by size payload bytes.
func readMultiplexed(r io.Reader, maxFrame int, emit func(logLine)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [8]byte
	var prev time.Time
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		size := int(binary.BigEndian.Uint32(hdr[4:]))
		stream := streamName(hdr[0])
		keep := size
		if keep > maxFrame {
			keep = maxFrame
		}
		payload := make([]byte, keep)
		if _, err := io.ReadFull(br, payload); err != nil {
			return err
		}
		if size > keep {
			if _, err := io.CopyN(io.Discard, br, int64(size-keep)); err != nil {
				return err
			}
		}
		for _, part := range bytes.Split(bytes.TrimRight(payload, "\r\n"), []byte("\n")) {
			ts, text := splitTimestamp(strings.TrimRight(string(part), "\r"), prev)
			prev = ts
			emit(logLine{stream: stream, ts: ts, text: text})
		}
	}
}

// readRaw parses the log stream of a container with a TTY: plain lines, all on stdout.
func readRaw(r io.Reader, maxLine int, emit func(logLine)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var prev time.Time
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if len(line) > maxLine {
				line = line[:maxLine]
			}
			ts, text := splitTimestamp(line, prev)
			prev = ts
			emit(logLine{stream: "stdout", ts: ts, text: text})
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// watcher polls the running containers and keeps one follower per container. It remembers the time of the last
// line shipped per container, so a container that restarts is resumed without duplicates.
type watcher struct {
	cfg    config
	docker *dockerClient
	sink   *sink
	log    *limitedLog

	mu     sync.Mutex
	active map[string]bool
	last   map[string]time.Time
	// retryAt holds back containers whose logs could not be opened (for example the "none" log driver), so they
	// are not asked again on every poll.
	retryAt map[string]time.Time
}

// followRetry is how long a container whose logs could not be opened is left alone.
const followRetry = time.Minute

func newWatcher(cfg config, d *dockerClient, s *sink, lg *limitedLog) *watcher {
	return &watcher{cfg: cfg, docker: d, sink: s, log: lg, active: map[string]bool{}, last: map[string]time.Time{},
		retryAt: map[string]time.Time{}}
}

func (w *watcher) loop(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		list, err := w.docker.running(ctx)
		if err != nil && ctx.Err() == nil {
			w.log.printf("docker", "listing containers: %v", err)
		}
		for _, c := range list {
			w.mu.Lock()
			busy := w.active[c.ID] || time.Now().Before(w.retryAt[c.ID])
			if !busy {
				w.active[c.ID] = true
			}
			w.mu.Unlock()
			if busy {
				continue
			}
			wg.Add(1)
			go func(c containerSummary) {
				defer wg.Done()
				w.follow(ctx, c)
				w.mu.Lock()
				delete(w.active, c.ID)
				w.mu.Unlock()
			}(c)
		}
		if !sleepCtx(ctx, w.cfg.pollInterval) {
			return
		}
	}
}

func (w *watcher) follow(ctx context.Context, c containerSummary) {
	tty, err := w.docker.tty(ctx, c.ID)
	if err != nil {
		if ctx.Err() == nil {
			w.log.printf("inspect:"+c.ID, "inspecting %s: %v", shortID(c.ID), err)
			w.holdBack(c.ID)
		}
		return
	}
	w.mu.Lock()
	since := w.last[c.ID]
	w.mu.Unlock()
	body, err := w.docker.follow(ctx, c.ID, since)
	if err != nil {
		if ctx.Err() == nil {
			w.log.printf("logs:"+c.ID, "following %s: %v", shortID(c.ID), err)
			w.holdBack(c.ID)
		}
		return
	}
	defer body.Close()
	labels := containerLabels(c)
	emit := func(l logLine) {
		// Docker's since filter is inclusive; skip what was already shipped.
		if !since.IsZero() && !l.ts.After(since) {
			return
		}
		since = l.ts
		w.mu.Lock()
		w.last[c.ID] = l.ts
		w.mu.Unlock()
		w.sink.add(c.ID, l, labels)
	}
	if tty {
		err = readRaw(body, w.cfg.maxLineBytes, emit)
	} else {
		err = readMultiplexed(body, w.cfg.maxLineBytes, emit)
	}
	if err != nil && ctx.Err() == nil {
		w.log.printf("stream:"+c.ID, "log stream of %s ended: %v", shortID(c.ID), err)
	}
}

func (w *watcher) holdBack(id string) {
	w.mu.Lock()
	w.retryAt[id] = time.Now().Add(followRetry)
	w.mu.Unlock()
}

func containerLabels(c containerSummary) map[string]string {
	name := c.ID
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	m := map[string]string{
		"container_name": name,
		"container_id":   shortID(c.ID),
		"image":          c.Image,
	}
	if v := c.Labels["com.docker.compose.service"]; v != "" {
		m["compose_service"] = v
	}
	if v := c.Labels["com.docker.compose.project"]; v != "" {
		m["compose_project"] = v
	}
	return m
}
